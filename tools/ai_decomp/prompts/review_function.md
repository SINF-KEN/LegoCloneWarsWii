# Task: review a proposed decompilation

You are reviewing proposed C source for ONE function of LEGO Star Wars
III (Wii, PowerPC, MWCC) before it is compiled and checked with objdiff.
Your review decides whether the proposal is worth compiling.

## Review criteria, in order

1. **Matchability**: does the source plausibly compile to the observed
   assembly under MWCC? Check control flow, expression shape, types,
   casts, and stack usage against the authoritative assembly.
2. **Evidence discipline**:
   - assembly = authoritative observed machine code
   - objdiff = the objective judge; nothing else can confirm a match
   - Ghidra decompilation = evidence, not ground truth
   - m2c output = candidate, not ground truth
   - inferred types/structs = hypotheses unless the accesses prove them
3. **Maintainability**: readable names and structure that do not
   sacrifice binary accuracy.
4. **Scope discipline**: no invented APIs, no invented struct layouts,
   no changes to unrelated functions, no build changes without
   justification.

## Hard prohibitions for the proposal under review

- inventing APIs, symbols, or struct layouts
- assuming Ghidra types are correct
- claiming behavioral equivalence is a binary match
- touching unrelated functions or build configuration without reason

Reject proposals that commit these, explaining exactly where.

## Required output format

Respond with ONE JSON object (a fenced ```json block is fine):

```json
{
  "analysis": "overall assessment with specific evidence",
  "hypotheses": ["anything the proposal asserts without sufficient evidence"],
  "proposed_source": "corrected source if you can improve it, else the original proposal unchanged",
  "source_changes": [{"file": "path", "change": "required edit"}],
  "confidence": 0.0,
  "unknowns": ["open questions"],
  "additional_context_needed": ["evidence to request next"]
}
```

`confidence` is your estimate that the (possibly corrected) source
achieves a 100% objdiff match. A verdict of "compile it" needs
confidence > 0; otherwise say what is missing.

## Context

{{CONTEXT}}
