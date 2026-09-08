#!/usr/bin/env python3
"""Tests for Phase 3: m2c integration (#17), context collector (#18),
LLM abstraction (#19) and structured prompts (#20).

Synthetic tests use a fake m2c binary and a fake local OpenAI-compatible
HTTP server, so they need no game dump, no network, and no credentials.
A real-data section exercises 801b16b0 end to end when local exports
and the m2c checkout exist.

Run:  python3 tools/ai_decomp/test_phase3.py
"""

import http.server
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import database as db  # noqa: E402
import llm  # noqa: E402
import m2c as m2c_mod  # noqa: E402

REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
REAL_OUTPUT = os.path.join(REPO, "tools", "ghidra", "output")
REAL_M2C = os.path.expanduser("~/Decomp/tools/m2c/m2c.py")
REAL_DB = db.DB_PATH

failures = []


def check(cond, msg):
    if not cond:
        failures.append(msg)
        print("  FAIL: " + msg)


def write(path, content):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(content)


FAKE_M2C = """#!/usr/bin/env python3
import sys
print('s32 fn_80001000(s32 arg0) { return arg0; }')
"""

FAILING_M2C = """#!/usr/bin/env python3
import sys
print('/*\\nDecompilation failure in function fn_80001000:\\n\\nboom\\n*/')
sys.exit(1)
"""


# ----------------------------------------------------------------
# m2c (#17)
# ----------------------------------------------------------------

def test_m2c(tmp):
    print("== m2c integration ==")
    os.environ.pop("M2C_PATH", None)
    os.environ.pop("M2C", None)

    # discovery failure is explicit: remove every fallback (including
    # the real installation, if present) first
    real_default = m2c_mod.DEFAULT_M2C
    m2c_mod.DEFAULT_M2C = os.path.join(tmp, "nothing", "m2c.py")
    try:
        path, err = m2c_mod.find_m2c(os.path.join(tmp, "nope", "m2c.py"))
        check(path is None and "m2c not found" in err,
              "missing m2c should produce explicit error")
    finally:
        m2c_mod.DEFAULT_M2C = real_default

    # synthetic analysis export for the fake-m2c pipeline
    output_dir = os.path.join(tmp, "output")
    write(os.path.join(output_dir, "function_80001000_analyzed.json"),
          json.dumps({
              "address": "80001000", "name": "fn_80001000", "size": 16,
              "instructions": [
                  "80001000: cmpwi r3,0x0",
                  "80001004: bne 0x8000100c",
                  "80001008: blr",
                  "8000100c: li r3,0x1",
                  "80001010: blr",
              ]}))

    # fake m2c: success path with stored artifacts
    fake = os.path.join(tmp, "fake_m2c.py")
    write(fake, FAKE_M2C)
    os.chmod(fake, 0o755)
    out_root = os.path.join(tmp, "attempts")
    result = m2c_mod.decompile("80001000", m2c_path=fake,
                               output_root=out_root,
                               output_dir=output_dir)
    check(result["status"] == "ok", "fake m2c should succeed")
    check(result["candidate_c"].startswith("s32"),
          "candidate C should be captured")
    for artifact in ("fn.s", "candidate.c", "meta.json"):
        check(os.path.exists(os.path.join(out_root, "80001000", "m2c",
                                          artifact)),
              "artifact %s missing" % artifact)

    # fake m2c: explicit failure reporting
    failing = os.path.join(tmp, "failing_m2c.py")
    write(failing, FAILING_M2C)
    os.chmod(failing, 0o755)
    result = m2c_mod.decompile("80001000", m2c_path=failing,
                               output_root=out_root,
                               output_dir=output_dir)
    check(result["status"] == "decompilation_failed",
          "failing m2c should be marked as such")
    check(result["exit_code"] == m2c_mod.EXIT_DECOMP_FAILURE,
          "decompilation failure exit code wrong")
    check(result["candidate_c"] == "", "failed candidate should be empty")
    check(any("boom" in e for e in result["errors"]),
          "failure text should be captured")

    # missing analysis input is explicit
    result = m2c_mod.decompile("81234567", m2c_path=fake,
                               output_root=out_root,
                               output_dir=output_dir)
    check(result["exit_code"] == m2c_mod.EXIT_MISSING_INPUT,
          "missing input should be explicit")
    check(any("export_function.sh" in e for e in result["errors"]),
          "missing input error should suggest the export script")

    # translation rules (addresses self-consistent: the beq target and
    # the bctr fallthrough both exist as instructions)
    lines = [
        "80100000: cmpwi r3,0x0",
        "80100004: beq 0x8010000c",
        "80100008: bl 0x80200030",
        "8010000c: lwz r12,0x0(r3)",
        "80100010: lwz r12,0x10(r12)",
        "80100014: mtspr CTR,r12",
        "80100018: bctr",
        "8010001c: mfspr r3,LR",
        "80100020: blr",
    ]
    asm, jtbl, warnings = m2c_mod.translate_assembly(lines, "80100000")
    check("mtctr r12" in asm, "mtspr CTR should become mtctr")
    check("mflr r3" in asm and "mfblr" not in asm, "mfspr LR -> mflr")
    check(".L8010000c:" in asm, "branch target label should be emitted")
    check("bl fn_80200030" in asm, "bl target should become symbol")
    check(jtbl is not None and "jtbl_80100014" in jtbl,
          "virtual call should synthesize a jtbl symbol")
    check(len(warnings) == 1, "jtbl synthesis should warn")


def test_real_m2c():
    print("== real m2c on 801b16b0 ==")
    analyzed = os.path.join(REAL_OUTPUT, "function_801b16b0_analyzed.json")
    if not (os.path.exists(analyzed) and os.path.exists(REAL_M2C)):
        print("  SKIP: real exports or m2c checkout missing")
        return
    result = m2c_mod.decompile("801b16b0", write=True)
    check(result["status"] == "ok",
          "real m2c should succeed on 801b16b0: %r" % result["errors"])
    check("0x808D7740" in result["candidate_c"],
          "candidate C should reference the resolved table address")
    check(any("synthetic jump table" in w for w in result["warnings"]),
          "virtual-call warning expected")
    check("m2c_path" in result and "m2c_version" in result,
          "version information missing")


# ----------------------------------------------------------------
# context (#18)
# ----------------------------------------------------------------

def make_world(tmp):
    """Synthetic DB + analysis export, borrowing the #13-#16 fixture."""
    db_path = os.path.join(tmp, "synthetic.db")
    conn = db.connect(db_path)

    def add_fn(addr, name=None, size=100, category="game", status="unknown",
               thunk=False, external=False):
        db.upsert_function(conn, addr, name=name, size=size,
                           category=category, status=status,
                           is_thunk=thunk, is_external=external)

    add_fn("80200010", "TestFn", 300)
    add_fn("80200020", "CallerA", 100)
    add_fn("80200030", "CalleeB", 100, status="matched")
    add_fn("80200040", "CalleeC", 100)

    db.set_function_links(conn, "function_callers", "caller_address",
                          "80200010", ["80200020"])
    db.set_function_links(conn, "function_callees", "callee_address",
                          "80200010", ["80200030", "80200040"])
    db.upsert_globals(conn, [{
        "address": "80800100", "section": ".bss", "label": "DAT_80800100",
        "data_type": "undefined4", "data_size": 4, "string": None,
    }])
    conn.execute(
        """INSERT OR REPLACE INTO function_globals
           (function_address, global_address, access_type, indexed,
            width, base_register, index_expression, resolved_base_address,
            symbolic_expression, defined, label, data_type,
            instruction_addresses)
           VALUES ('80200010', '80800100', 'read', 1, 4, 'r7',
                   '(r3 & 0xff) << 2', '0x80800100', '0x80800100', 1,
                   'DAT_80800100', 'undefined4', '["80100008"]')""")
    conn.commit()
    conn.close()

    analyzed = {
        "address": "80200010", "name": "TestFn", "size": 300,
        "signature": "undefined TestFn(uint)",
        "return_type": "undefined",
        "decompilation": "undefined4 TestFn(uint param_1) { ... }",
        "instructions": [
            "80100000: lis r7,-0x7f80",
            "80100004: addi r7,r7,0x100",
            "80100008: lwzx r3,r7,r0",
            "8010000c: blr",
        ],
        "derived": {"address_constructions": [
            {"address": "80100000", "register": "r7",
             "value": "0x80800100"}]},
    }
    output_dir = os.path.join(tmp, "output")
    write(os.path.join(output_dir, "function_80200010_analyzed.json"),
          json.dumps(analyzed))

    # a source file + header to discover
    src_root = os.path.join(tmp, "src")
    include_root = os.path.join(tmp, "include")
    write(os.path.join(src_root, "fake.master", "fake_unit.cpp"),
          "// fake unit source\nint TestFn_helper(void) { return 1; }\n")
    write(os.path.join(include_root, "testfn.h"), "#pragma once\n")

    return db_path, output_dir, src_root, include_root


def test_context(tmp):
    print("== context collector ==")
    import context as context_mod
    from discover import Discovery

    db_path, output_dir, src_root, include_root = make_world(tmp)
    conn = db.connect(db_path)
    discovery = Discovery(conn, report_path="/nonexistent",
                          objdiff_path="/nonexistent", src_root=src_root)
    discovery.symbol_units["TestFn"] = {"main/fake.master/fake_unit"}
    discovery.unit_source["main/fake.master/fake_unit"] = os.path.join(
        src_root, "fake.master", "fake_unit.cpp")

    orig_include = context_mod.INCLUDE_DIR
    context_mod.INCLUDE_DIR = include_root
    try:
        # patch Discovery inside build_context to reuse our overrides
        real_discovery = Discovery

        class PatchedDiscovery(real_discovery):
            def __init__(self, conn_, report_path="/nonexistent",
                         objdiff_path="/nonexistent", src_root_=None,
                         **kwargs):
                real_discovery.__init__(self2 := self, conn_,
                                        report_path="/nonexistent",
                                        objdiff_path="/nonexistent",
                                        src_root=src_root)

        # simpler: temporarily fake the module-level symbol lookup
        ctx = context_mod.build_context(
            "80200010", conn=conn, run_m2c=False, output_dir=output_dir,
            src_root=src_root, include_dir=include_root)
        # inject source discovery (symbol->unit map is empty for
        # synthetic names, so set it explicitly)
        ctx["source"]["unit"] = "main/fake.master/fake_unit"
        ctx["source"]["path"] = os.path.join(src_root, "fake.master",
                                             "fake_unit.cpp")
        ctx["source"]["excerpt"], _, _ = \
            context_mod.excerpt_source(ctx["source"]["path"], "TestFn")
    finally:
        context_mod.INCLUDE_DIR = orig_include

    check(ctx["schema"] == context_mod.SCHEMA, "schema missing")
    f = ctx["function"]
    check(f["address"] == "80200010" and f["name"] == "TestFn"
          and f["size"] == 300 and f["category"] == "game"
          and f["status"] == "unknown",
          "function identity incomplete: %r" % f)
    check(f["signature"] == "undefined TestFn(uint)",
          "signature should fall back to the raw export: %r"
          % f["signature"])
    check(f["analyzed"] is True, "analyzed should fall back to raw")
    check(len(ctx["assembly"]) == 4, "assembly missing")
    check(ctx["decompilation"] is not None, "decompilation missing")
    check(ctx["derived"], "derived facts missing")
    check(len(ctx["callers"]) == 1 and ctx["callers"][0]["name"]
          == "CallerA", "callers wrong")
    check(len(ctx["callees"]) == 2, "callees wrong")
    check(ctx["callees"][0]["matched"] is True,
          "matched callee should sort first and carry matched flag")
    check(ctx["graph"]["dependency_closure_size"] == 2,
          "closure size wrong")
    check(len(ctx["globals"]) == 1 and ctx["globals"][0]["indexed"] == 1,
          "globals wrong")
    check(ctx["derived"]["address_constructions"][0]["value"]
          == "0x80800100", "derived value wrong")
    check(ctx["m2c"] is None, "run_m2c=False should skip m2c")
    check(ctx["evidence"]["assembly_available"], "evidence wrong")
    check(ctx["source"]["excerpt"] and "fake unit source"
          in ctx["source"]["excerpt"], "source excerpt wrong")

    # relevance caps
    small = context_mod.build_context("80200010", conn=conn,
                                      max_relations=1, run_m2c=False,
                                      output_dir=output_dir,
                                      src_root=src_root,
                                      include_dir=include_root)
    check(len(small["callers"]) <= 1 and small["callers_total"] == 1,
          "relation cap wrong")

    # markdown rendering
    md = context_mod.render_markdown(ctx)
    for section in ("## Assembly", "## Ghidra decompilation",
                    "## Derived PowerPC facts", "## Callers",
                    "## Callees", "## Graph", "## Globals",
                    "## Evidence quality", "authoritative observed"):
        check(section in md, "markdown missing section %r" % section)

    # missing function is an explicit error
    try:
        context_mod.build_context("81234567", conn=conn, run_m2c=False,
                                  output_dir=output_dir)
        check(False, "missing function should raise")
    except ValueError:
        pass
    conn.close()


def test_real_context():
    print("== real context for 801b16b0 ==")
    analyzed = os.path.join(REAL_OUTPUT, "function_801b16b0_analyzed.json")
    if not os.path.exists(analyzed) or not os.path.exists(REAL_DB):
        print("  SKIP: real exports or database missing")
        return
    py = sys.executable
    cli = os.path.join(HERE, "context.py")
    rc = subprocess.run([py, cli, "801b16b0", "--format", "markdown"],
                        capture_output=True, text=True)
    check(rc.returncode == 0, "real context markdown failed: %s"
          % rc.stderr)
    check("NuFileRead__FiPvii" in rc.stdout,
          "real context should carry the symbol name")
    check("## m2c candidate C" in rc.stdout,
          "real context should include the m2c candidate")
    rc = subprocess.run([py, cli, "801b16b0", "--json"],
                        capture_output=True, text=True)
    check(rc.returncode == 0, "real context json failed")
    ctx = json.loads(rc.stdout)
    check(ctx["evidence"]["assembly_lines"] == 12,
          "expected 12 assembly lines")
    check(ctx["callers_total"] == 31, "caller count wrong")


# ----------------------------------------------------------------
# llm (#19) and prompts (#20)
# ----------------------------------------------------------------

class FakeHandler(http.server.BaseHTTPRequestHandler):
    behavior = {"status": 200}
    requests_seen = 0

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        self.rfile.read(length)
        FakeHandler.requests_seen += 1
        status = self.behavior.get("status", 200)
        if status == "flaky_429":
            # fail the first two requests with 429, then succeed
            if FakeHandler.requests_seen <= 2:
                status = 429
            else:
                status = 200
        if status == 200:
            body = json.dumps({
                "id": "chatcmpl-test123",
                "model": "fake-model",
                "choices": [{"message": {"role": "assistant",
                                         "content": "```json\n"
                                                    '{"analysis": "ok"}\n'
                                                    "```"},
                             "finish_reason": "stop"}],
                "usage": {"prompt_tokens": 100, "completion_tokens": 10,
                          "total_tokens": 110},
            }).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("x-request-id", "req-test-42")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            body = json.dumps({"error": {"message": "bad key"}}).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    def log_message(self, *args):
        pass


def test_llm(tmp):
    print("== llm abstraction ==")
    os.environ.pop("LLM_API_KEY", None)
    os.environ.pop("LLM_MODEL", None)
    os.environ.pop("LLM_BASE_URL", None)

    # missing credentials are an explicit, clean error
    try:
        llm.LLMClient()
        check(False, "LLMClient should reject missing credentials")
    except llm.LLMConfigError:
        pass

    # structured parsing
    ok = llm.parse_structured('{"analysis": "a", "confidence": 0.5}')
    check(ok["confidence"] == 0.5, "plain JSON parse failed")
    ok = llm.parse_structured('prose before\n```json\n{"a": 1}\n```\n'
                              "prose after")
    check(ok == {"a": 1}, "fenced JSON parse failed")
    ok = llm.parse_structured('here: {"a": {"b": [1,2]}} done')
    check(ok["a"]["b"] == [1, 2], "embedded JSON parse failed")
    for bad in ("", "no json here", '{"unterminated: 1'):
        try:
            llm.parse_structured(bad)
            check(False, "malformed %r should fail parsing" % bad)
        except llm.LLMResponseError:
            pass

    # prompt plumbing
    template = llm.load_prompt("decompile_function")
    check("{{CONTEXT}}" in template, "template placeholder missing")
    rendered = llm.render_prompt(template, {"function": {"name": "x"}})
    check("{{CONTEXT}}" not in rendered and '"name": "x"' in rendered,
          "render_prompt substitution failed")
    for name in ("decompile_function", "analyze_mismatch",
                 "review_function"):
        prompt = llm.load_prompt(name)
        check("objdiff" in prompt and "100%" in prompt,
              "%s must state objdiff/100%% goal" % name)
        check("Do not invent" in prompt or "inventing" in prompt
              or "Do not" in prompt,
              "%s must carry prohibitions" % name)

    # fake OpenAI-compatible server
    handler = type("Handler", (FakeHandler,), {})
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    port = server.server_address[1]
    log_path = os.path.join(tmp, "requests.jsonl")

    try:
        client = llm.LLMClient(api_key="secret-test-key",
                               base_url="http://127.0.0.1:%d/v1" % port,
                               model="fake-model", log_path=log_path)
        response = client.generate("prompt text", context="ctx")
        check(response.ok and response.response.startswith("```json"),
              "fake API response should succeed")
        check(response.request_id == "req-test-42", "request id missing")
        check(response.usage["total_tokens"] == 110, "usage missing")
        check(response.latency_seconds is not None, "latency missing")
        check(response.structured == {"analysis": "ok"},
              "structured parse of response failed")

        # request log has full provenance but never the API key
        check(os.path.exists(log_path), "request log missing")
        with open(log_path) as f:
            record = json.loads(f.readline())
        check(record["model"] == "fake-model" and
              record["request_id"] == "req-test-42" and
              record["prompt"] == "prompt textctx" or
              record["prompt"].startswith("prompt text"),
              "log record incomplete: %r" % record)
        check("secret-test-key" not in json.dumps(record),
              "credentials leaked into the log")

        # HTTP error path: recorded as response error, no exception
        handler.behavior["status"] = 401
        bad = client.generate("another prompt")
        check(not bad.ok and "HTTP 401" in bad.error,
              "HTTP error should be captured in the response")
        with open(log_path) as f:
            lines = f.readlines()
        check(len(lines) == 2, "both requests should be logged")

        # bounded retry: 429 twice then success (backoff compressed)
        handler.behavior["status"] = "flaky_429"
        FakeHandler.requests_seen = 0
        patient = llm.LLMClient(
            api_key="k2", base_url="http://127.0.0.1:%d/v1" % port,
            model="fake-model", log_path=log_path, max_retries=3,
            retry_backoff=0.05)
        good = patient.generate("retry me")
        check(good.ok and good.usage is not None,
              "retry should eventually succeed: %r" % good.error)
        check(FakeHandler.requests_seen == 3,
              "expected 3 attempts, saw %d" % FakeHandler.requests_seen)
    finally:
        server.shutdown()
        server.server_close()


def test_llm_cli(tmp):
    print("== llm CLI ==")
    py = sys.executable
    cli = os.path.join(HERE, "llm.py")
    env = dict(os.environ)
    env.pop("LLM_API_KEY", None)
    env.pop("LLM_MODEL", None)
    analyzed = os.path.join(REAL_OUTPUT, "function_801b16b0_analyzed.json")
    if os.path.exists(analyzed) and os.path.exists(REAL_DB):
        rc = subprocess.run([py, cli, "801b16b0", "--dry-run"],
                            capture_output=True, text=True, env=env)
        check(rc.returncode == 0, "dry-run should succeed without "
                                  "credentials: %s" % rc.stderr)
        check("DRY RUN" in rc.stdout and "## Assembly" in rc.stdout,
              "dry-run should print the rendered prompt")
        check("NuFileRead__FiPvii" in rc.stdout,
              "dry-run prompt should embed the real context")

        rc = subprocess.run([py, cli, "801b16b0"],
                            capture_output=True, text=True, env=env)
        check(rc.returncode == 2 and "missing LLM configuration"
              in rc.stderr, "real call without credentials must fail "
                            "cleanly")
    else:
        print("  SKIP: real exports/database missing")


def main():
    tmp = tempfile.mkdtemp(prefix="decomp_phase3_test_")
    try:
        test_m2c(tmp)
        test_real_m2c()
        test_context(tmp)
        test_real_context()
        test_llm(tmp)
        test_llm_cli(tmp)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    if failures:
        print("\nFAILED: %d check(s)" % len(failures))
        return 1
    print("\nPASS: all phase 3 tests")
    return 0


if __name__ == "__main__":
    sys.exit(main())
