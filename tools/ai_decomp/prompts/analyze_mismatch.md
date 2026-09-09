# Task: analyze an objdiff mismatch

You are given a context package for ONE function of LEGO Star Wars III
(Wii, PowerPC, MWCC) whose current source does NOT match the original
binary. The objdiff report shows the compiled output differs from the
original — your job is to explain the difference and propose a minimal,
targeted source change.

## The previous candidate

The previous candidate is the current **objectively verified best
candidate** (its objdiff score is shown below). Do not throw it away
unnecessarily — improve it rather than starting over. Its changes are
already applied to the file you are editing.

When the context contains an "Objective mismatch evidence" section, it
is a byte-level comparison of the extracted original object against
your built candidate. Prioritize differences in this order:

1. exact instruction mismatch (expected vs actual word)
2. instruction ordering
3. register mismatch
4. load/store mismatch
5. branch mismatch
6. immediate/address mismatch
7. call/return mismatch
8. function size mismatch
9. aggregate byte mismatch

Describe what the evidence shows; do not claim a semantic cause the
bytes do not support. The `actual` side is raw hex — the pipeline does
not disassemble your output for you.

## Evidence hierarchy

1. **The original assembly is authoritative.** The compiled output must
   become byte-identical to it — a 100% objdiff match, not merely
   equivalent behavior.
2. **objdiff is the objective judge.** Its diff output (instruction
   mismatches, register allocation differences, stack layout deltas) is
   the primary evidence for this task.
3. **Compiler behavior matters.** Explain differences in terms of MWCC
   code generation: expression shape, promotion rules, cast placement,
   loop form, inlining, register pressure, stack slot ordering.
4. **Ghidra decompilation is evidence, not ground truth.**
5. **m2c output is a candidate, not ground truth.**
6. **Inferred types are hypotheses unless the accesses prove them.**

## Known compiler idioms

If the context contains a "Known MWCC compiler idioms" section, those
are patterns previously observed in real compilations of this project,
with their objdiff outcomes. Treat them as evidence for what MWCC
tends to emit — never as guarantees or rules. Always verify a proposed
construct against the target assembly and, ultimately, objdiff.

## Type / struct / vtable evidence

If the context contains a "Type / object evidence" section, use it to
explain compiler-generated access patterns: field offsets and widths,
vtable pointer locations, virtual slot indices, and register roles.
Type evidence may explain why MWCC emits certain loads and calls, but
it is not authoritative. Prefer a simpler source construct when the
inferred type is uncertain; if evidence conflicts, state the
uncertainty instead of forcing a type.

## Related functions

"Related functions" (when present) are selected by deterministic
relevance scoring: higher-ranked items share stronger structural or
dependency evidence with the target (direct calls, shared globals,
shared virtual slots or strings). They are useful references for
inferring compiler and source idioms, but their source code is not
authoritative for the target:

- do not copy unrelated implementations;
- do not assume shared globals imply shared types;
- do not assume shared virtual slots imply identical classes;
- resolve conflicts using the target assembly.

## Function naming convention (critical for objdiff)

The context reports the target's mangled symbol (e.g.
`NuFileRead__FiPvii`) and, when recoverable, a `cpp_name_hint` (e.g.
`NuFileRead`). Write your function using the DEMANGLED C++ signature —
**never the mangled name as an identifier**. `void NuFlip4(void*)`
compiles to symbol `NuFlip4__FPv`; writing `void NuFlip4__FPv(...)`
double-mangles and objdiff can never pair it.

## Hard prohibitions

## Hard prohibitions

- Do not invent APIs or symbols not present in the context.
- Do not invent struct layouts that observed accesses do not prove.
- Do not assume Ghidra's types are correct.
- Do not change unrelated functions.
- Do not modify build configuration unless explicitly justified.
- Never treat "behaves the same" as "matches the binary".
- No hidden chain-of-thought: concise conclusions with evidence only.

## Required output format

Respond with ONE JSON object (a fenced ```json block is fine):

```json
{
  "analysis": "the most likely cause of the mismatch, tied to specific differing instructions",
  "hypotheses": ["candidate causes ranked by likelihood, with evidence"],
  "proposed_source": "revised source for the function",
  "source_changes": [
    {
      "path": "src/<unit-file>.cpp",
      "operation": "replace",
      "old_text": "the exact current text being replaced (verbatim, unique in the file)",
      "new_text": "the replacement text"
    }
  ],
  "confidence": 0.0,
  "unknowns": ["what remains unexplained"],
  "additional_context_needed": ["evidence that would disambiguate the remaining hypotheses"]
}
```

`source_changes` are applied automatically: `path` must be the exact
existing file path from the context, `operation` is `replace`,
`append`, or `create`, and `old_text` for `replace` must appear
verbatim and exactly once — otherwise the change is refused.

`confidence` is your estimate that the revised source closes the
objdiff diff completely.

## Context

{{CONTEXT}}
