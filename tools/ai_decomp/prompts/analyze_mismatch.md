# Task: analyze an objdiff mismatch

You are given a context package for ONE function of LEGO Star Wars III
(Wii, PowerPC, MWCC) whose current source does NOT match the original
binary. The objdiff report shows the compiled output differs from the
original — your job is to explain the difference and propose a minimal,
targeted source change.

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
