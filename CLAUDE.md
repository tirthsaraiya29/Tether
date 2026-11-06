# Tether — Token-Optimized System Directives

## 1. Output & Diff Generation Rules (STRICT)
- **Zero Full-File Rewrites:** NEVER output, re-generate, or echo entire files when modifying code.
- **Surgical Edits Only:** Always use localized string replacement tools (`Edit` / `str_replace`) with minimal necessary context lines (max 3 lines before/after).
- **Prohibit Redundant Explanations:** Do not explain code changes or narrate your thought process after executing an edit. Present only the action taken and its direct result.
- **Conciseness Floor:** Keep conversational responses strictly under 3 sentences unless specifically requested to perform an architectural review.

## 2. Terminal & Tool Execution Discipline
- **Silence Compiler & Build Output:** When executing builds or tests, pipe stdout to suppress success noise while keeping errors:
  - C# / .NET: Use `dotnet build -v q --nologo` or `dotnet test --logger "console;verbosity=minimal"`.
  - Native / C++: Append quiet flags to avoid spamming the message history with compilation object lists.
- **Paging & Grep Containment:**
  - NEVER dump raw logs, long directory listings, or full files into the context using `cat` or `Get-Content`.
  - Always bound search output: Use `ripgrep` (`rg -m 10`) or `git grep` with line limits.
  - When inspecting unfamiliar files, use `head`, `tail`, or read offset ranges (maximum 50–100 lines at a time).
- **Silent Git Hygiene:** Run `git status -s` (short format) instead of standard verbose `git status`.

## 3. Autonomous Loop Constraints
- **Immediate Termination on Success:** Once a compilation fix or refactoring goal builds without errors, terminate the turn immediately. Do not speculate on follow-up tasks or run unprompted verification passes.
- **Fast-Fail Rule:** If a build command fails with more than 5 compiler errors, stop and inspect only the first 2 errors. Do not run multi-stage diagnostics before addressing primary syntax/type issues.
- **Single-Turn Scoping:** Avoid chaining exploratory bash commands when a static AST search or targeted grep can resolve the location in one step.

## 4. Context Preservation
- **No Scratchpad Duplication:** Do not echo intermediate state, JSON payloads, or raw IPC buffers back into the conversation channel.
- **Reference Over Repetition:** Refer to functions, symbols, and files by their identifier paths rather than copying source snippets into the chat.
