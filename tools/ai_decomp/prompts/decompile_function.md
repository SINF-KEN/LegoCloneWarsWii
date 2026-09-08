# Task: produce matching C for a PowerPC function

You are given a focused context package for ONE function of LEGO Star
Wars III: The Clone Wars (Wii, PowerPC 750CX "Gekko"/"Broadway", compiled
with Metrowerks CodeWarrior / MWCC).

## The goal — read this carefully

**The goal is to write C source that compiles to the EXACT original
machine code — a 100% binary match as judged by objdiff.**

- Do NOT merely reproduce equivalent behavior.
- Do NOT write "reasonable" or "plausible" code.
- Code that behaves the same but compiles differently is a FAILURE.

## Evidence hierarchy

1. **Assembly** (the `## Assembly` section) is the authoritative observed
   machine code. Every instruction must be accounted for by your source.
2. **objdiff** is the only objective judge of correctness. Its verdict
   overrides every other signal, including your own confidence.
3. **Compiler behavior matters.** The binary was built with MWCC for
   PowerPC. Idioms (register allocation, stack frames, struct offsets,
   inlining, implicit casts, switch lowering) follow MWCC conventions.
   When assembly and your intuition disagree, trust the assembly and
   reverse-engineer the source shape that would produce it.
4. **Ghidra decompilation** is evidence and a convenience — NOT ground
   truth. Its types are frequently wrong (`undefined`, `undefined4`).
5. **m2c output** is a candidate translation — NOT ground truth. It may
   misrepresent virtual calls and jump tables.
6. **Inferred types and struct layouts are hypotheses** unless directly
   supported by the evidence (observed access widths, offsets, callers,
   and callees).

## Hard prohibitions

- Do not invent APIs, functions, or symbols that are not in the context.
- Do not invent struct layouts that the accesses do not prove.
- Do not assume Ghidra's types are correct.
- Do not change unrelated functions or files.
- Do not modify build configuration unless you explicitly justify it.
- Never claim a behavioral match is a binary match. Only objdiff decides.
- Do not produce hidden chain-of-thought; give concise conclusions and
  the evidence for them.

## Required output format

Respond with ONE JSON object (a fenced ```json block is fine) and
nothing else:

```json
{
  "analysis": "concise explanation of what the function does and how the evidence leads to the proposed source",
  "hypotheses": ["each type/struct/behavior guess with its supporting evidence"],
  "proposed_source": "the complete C (or C++) source for this function",
  "source_changes": [{"file": "path if known", "change": "description"}],
  "confidence": 0.0,
  "unknowns": ["facts that could not be established from the context"],
  "additional_context_needed": ["specific evidence that would improve the next attempt"]
}
```

`confidence` is your estimate that `proposed_source` will achieve a
100% objdiff match as-is. Be honest; low confidence is useful signal.

## Context

{{CONTEXT}}
