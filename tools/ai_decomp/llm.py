#!/usr/bin/env python3
"""LLM API abstraction for the AI decompilation pipeline (roadmap #19).

Provider-agnostic: any OpenAI-compatible chat-completions endpoint
works. Configuration comes exclusively from environment variables —
never hardcode credentials, never commit them:

    LLM_API_KEY    API token (required for real requests)
    LLM_BASE_URL   API base (default https://api.openai.com/v1)
    LLM_MODEL      model name (required for real requests)

Python interface:

    from llm import LLMClient, load_prompt, render_prompt, parse_structured
    client = LLMClient()                     # raises LLMConfigError w/o env
    result = client.generate(prompt, context=ctx_json_or_markdown)
    result.response          # assistant text
    result.usage             # token usage if the API reports it
    result.latency_seconds, result.request_id, result.error, ...

Every request (success or failure) is appended to
tools/ai_decomp/attempts/llm/requests.jsonl with model, request id,
timestamp, prompt, response, token usage, latency and error information.
Credentials are never written to the log.

`--dry-run` builds the full prompt from context.py and prints it
without any network activity and without needing credentials.

No automatic source modification and no retry loop happen here.
"""

import argparse
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import database as db  # noqa: E402

ATTEMPTS_DIR = os.path.join(HERE, "attempts")
REQUEST_LOG = os.path.join(ATTEMPTS_DIR, "llm", "requests.jsonl")
PROMPTS_DIR = os.path.join(HERE, "prompts")

DEFAULT_BASE_URL = "https://api.openai.com/v1"
DEFAULT_TIMEOUT = 600  # reasoning models can take minutes; LLM_TIMEOUT overrides
DEFAULT_MAX_RETRIES = 3  # bounded retries for 429/5xx/disconnects
RETRY_BACKOFF_SECONDS = 20.0  # exponential: 20, 40, 80...
RETRYABLE_STATUS = {429, 500, 502, 503, 504}

PROMPT_TEMPLATE = "decompile_function"


class LLMConfigError(Exception):
    """Raised when required credentials/configuration are missing."""


class LLMResponseError(Exception):
    """Raised when the API response cannot be parsed."""


class LLMResponse:
    """One request/response cycle with full provenance."""

    def __init__(self, prompt, model=None, response=None, request_id=None,
                 usage=None, latency_seconds=None, error=None,
                 timestamp=None, structured=None):
        self.prompt = prompt
        self.model = model
        self.response = response
        self.request_id = request_id
        self.usage = usage
        self.latency_seconds = latency_seconds
        self.error = error
        self.timestamp = timestamp or time.strftime("%Y-%m-%dT%H:%M:%S%z")
        self.structured = structured

    @property
    def ok(self):
        return self.error is None and self.response is not None

    def to_dict(self):
        return {
            "timestamp": self.timestamp,
            "model": self.model,
            "request_id": self.request_id,
            "latency_seconds": self.latency_seconds,
            "usage": self.usage,
            "ok": self.ok,
            "error": self.error,
            "prompt": self.prompt,
            "response": self.response,
            "structured": self.structured,
        }


class LLMClient:
    """Minimal OpenAI-compatible chat-completions client."""

    def __init__(self, api_key=None, base_url=None, model=None,
                 timeout=None, log_path=REQUEST_LOG, max_retries=None,
                 retry_backoff=None):
        self.api_key = api_key if api_key is not None \
            else os.environ.get("LLM_API_KEY")
        self.base_url = (base_url if base_url is not None
                         else os.environ.get("LLM_BASE_URL")
                         or DEFAULT_BASE_URL).rstrip("/")
        self.model = model if model is not None \
            else os.environ.get("LLM_MODEL")
        self.timeout = timeout if timeout is not None \
            else int(os.environ.get("LLM_TIMEOUT") or DEFAULT_TIMEOUT)
        self.max_retries = max_retries if max_retries is not None \
            else int(os.environ.get("LLM_MAX_RETRIES")
                     or DEFAULT_MAX_RETRIES)
        self.retry_backoff = retry_backoff if retry_backoff is not None \
            else float(os.environ.get("LLM_RETRY_BACKOFF")
                       or RETRY_BACKOFF_SECONDS)
        self.log_path = log_path
        extra = os.environ.get("LLM_EXTRA_BODY")
        self.extra_body = json.loads(extra) if extra else {}

        missing = [name for name, value in (
            ("LLM_API_KEY", self.api_key),
            ("LLM_MODEL", self.model)) if not value]
        if missing:
            raise LLMConfigError(
                "missing LLM configuration: %s. Set the environment "
                "variables (never commit credentials)." % ", ".join(missing))

    # ----------------------------------------------------------------

    def generate(self, prompt, context=None, system=None, temperature=0.2,
                 max_tokens=None):
        """Send one chat completion; never raises on API errors — the
        returned LLMResponse carries the error instead."""
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        user_content = prompt
        if context is not None:
            user_content = "%s\n\n%s" % (prompt, context) \
                if isinstance(context, str) else prompt
        messages.append({"role": "user", "content": user_content})

        body = {
            "model": self.model,
            "messages": messages,
            "temperature": temperature,
        }
        if max_tokens:
            body["max_tokens"] = max_tokens
        if self.extra_body:
            body.update(self.extra_body)

        request = urllib.request.Request(
            self.base_url + "/chat/completions",
            data=json.dumps(body).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Authorization": "Bearer %s" % self.api_key,
            },
            method="POST")

        response = LLMResponse(prompt=user_content, model=self.model,
                               timestamp=time.strftime(
                                   "%Y-%m-%dT%H:%M:%S%z"))
        attempts = self.max_retries + 1
        started = time.time()

        for attempt_no in range(1, attempts + 1):
            try:
                with urllib.request.urlopen(request, timeout=self.timeout) \
                        as handle:
                    payload = json.loads(
                        handle.read().decode("utf-8"))
                    request_id = handle.headers.get("x-request-id")
                response.latency_seconds = round(time.time() - started, 3)
                response.request_id = request_id
                try:
                    response.response = _extract_choice(payload)
                except LLMResponseError as exc:
                    # malformed/empty payload: retrying rarely helps;
                    # record the outcome and stop
                    response.latency_seconds = round(
                        time.time() - started, 3)
                    response.error = str(exc)
                    response.usage = payload.get("usage")
                    finish = (payload.get("choices") or [{}])[0] \
                        .get("finish_reason") if payload.get("choices") \
                        else None
                    if finish:
                        response.error += " (finish_reason=%s)" % finish
                    break
                response.usage = payload.get("usage")
                try:
                    response.structured = parse_structured(
                        response.response)
                except LLMResponseError:
                    response.structured = None
                response.error = None
                break
            except urllib.error.HTTPError as exc:
                try:
                    detail = exc.read().decode("utf-8", "replace")[:2000]
                except OSError:
                    detail = ""
                response.request_id = exc.headers.get("x-request-id") \
                    if exc.headers else None
                response.error = "HTTP %s: %s" % (exc.code, detail)
                if exc.code not in RETRYABLE_STATUS \
                        or attempt_no >= attempts:
                    break
            except (urllib.error.URLError, OSError, ValueError) as exc:
                response.error = "%s: %s" % (type(exc).__name__, exc)
                if attempt_no >= attempts:
                    break
            # bounded exponential backoff before the next attempt
            time.sleep(self.retry_backoff * (2 ** (attempt_no - 1)))

        response.latency_seconds = response.latency_seconds or \
            round(time.time() - started, 3)
        self._log(response)
        return response

    def _log(self, response):
        """Append the full provenance record (no credentials)."""
        try:
            os.makedirs(os.path.dirname(self.log_path), exist_ok=True)
            with open(self.log_path, "a") as f:
                f.write(json.dumps(response.to_dict()) + "\n")
        except OSError:
            pass  # logging must never break the pipeline


def _extract_choice(payload):
    try:
        choice = payload["choices"][0]
        message = choice["message"]
        content = message.get("content")
        if content is None and isinstance(message.get("tool_calls"), list):
            content = json.dumps(message["tool_calls"])
        if content is None or not str(content).strip():
            details = choice.get("finish_reason") or "unknown"
            usage = payload.get("usage") or {}
            reasoning = (usage.get("completion_tokens_details") or {}) \
                .get("reasoning_tokens")
            hint = ""
            if reasoning:
                hint = (" (model spent %s tokens on reasoning without "
                        "producing content)" % reasoning)
            raise LLMResponseError(
                "empty message content, finish_reason=%s%s"
                % (details, hint))
        return content
    except (KeyError, IndexError, TypeError) as exc:
        raise LLMResponseError("unexpected API payload: %s" % exc)


# ----------------------------------------------------------------
# prompts
# ----------------------------------------------------------------

def load_prompt(name=PROMPT_TEMPLATE, prompts_dir=PROMPTS_DIR):
    """Load a prompt template from tools/ai_decomp/prompts/."""
    path = os.path.join(prompts_dir, name + ".md")
    if not os.path.exists(path):
        path = os.path.join(prompts_dir, name)
    if not os.path.exists(path):
        raise FileNotFoundError("prompt %r not found in %s"
                                % (name, prompts_dir))
    with open(path) as f:
        return f.read()


def render_prompt(template, context=None, **kwargs):
    """Substitute {{CONTEXT}} and other {{KEY}} placeholders."""
    text = template
    if context is not None:
        rendered = context if isinstance(context, str) \
            else json.dumps(context, indent=2)
        text = text.replace("{{CONTEXT}}", rendered)
    for key, value in kwargs.items():
        text = text.replace("{{%s}}" % key.upper(), str(value))
    return text


# ----------------------------------------------------------------
# structured response parsing
# ----------------------------------------------------------------

JSON_FENCE_RE = re.compile(
    r"```(?:json)?\s*\n(.*?)\n\s*```", re.DOTALL)


def parse_structured(text):
    """Extract the structured JSON object from a model response.

    Accepts a raw JSON object or a ```json fenced block (optionally
    surrounded by prose). Raises LLMResponseError on malformed output.
    """
    if not text or not text.strip():
        raise LLMResponseError("empty response")

    candidates = []
    fenced = JSON_FENCE_RE.findall(text)
    candidates.extend(fenced)
    candidates.append(text)

    for candidate in candidates:
        candidate = candidate.strip()
        if not candidate.startswith("{"):
            # slice from first { to matching last }
            start, end = candidate.find("{"), candidate.rfind("}")
            if start == -1 or end <= start:
                continue
            candidate = candidate[start:end + 1]
        try:
            parsed = json.loads(candidate)
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict):
            return parsed
    raise LLMResponseError(
        "no valid JSON object found in response (%d chars)"
        % len(text or ""))


# ----------------------------------------------------------------
# CLI
# ----------------------------------------------------------------

def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("address", help="function address")
    ap.add_argument("--prompt", default=PROMPT_TEMPLATE,
                    help="prompt template name (default: %s)"
                         % PROMPT_TEMPLATE)
    ap.add_argument("--format", choices=("json", "markdown"),
                    default="markdown",
                    help="context format fed to the model")
    ap.add_argument("--dry-run", action="store_true",
                    help="build the prompt but make no API request")
    ap.add_argument("--db", default=db.DB_PATH)
    ap.add_argument("--model", help="override LLM_MODEL")
    args = ap.parse_args(argv)

    # 1. context (no credentials needed)
    import context as context_mod
    conn = db.connect(args.db)
    try:
        ctx = context_mod.build_context(args.address, conn=conn)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    finally:
        conn.close()
    context_text = ctx if args.format == "json" \
        else context_mod.render_markdown(ctx)

    # 2. prompt
    template = load_prompt(args.prompt)
    prompt = render_prompt(template, context_text)

    if args.dry_run:
        print("=== DRY RUN (no API request) ===")
        print("model would be: %s"
              % (args.model or os.environ.get("LLM_MODEL") or
                 "(unset: LLM_MODEL required)"))
        print("context format: %s" % args.format)
        print("prompt chars:   %d" % len(prompt))
        print("--- prompt ---")
        print(prompt)
        return 0

    # 3. real request
    try:
        client = LLMClient(model=args.model)
    except LLMConfigError as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 2

    response = client.generate(prompt)
    if not response.ok:
        print("error: %s" % response.error, file=sys.stderr)
        return 3

    print("model:       %s" % response.model)
    print("request id:  %s" % response.request_id)
    print("latency:     %ss" % response.latency_seconds)
    print("usage:       %s" % json.dumps(response.usage or {}))
    print("--- response ---")
    print(response.response)
    return 0


if __name__ == "__main__":
    sys.exit(main())
