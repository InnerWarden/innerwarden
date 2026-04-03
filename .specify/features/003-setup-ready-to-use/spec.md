# Feature: Setup Ready To Use

## Origin
User feedback on the first-use experience: `innerwarden setup` must leave the system ready in one pass, with fewer choices, clearer copy, and agent connection built into the wizard.

## Problem
The old setup mixed hidden changes, inconsistent wording, multiple follow-up commands, and an unclear finish line. A basic user could finish the wizard and still feel unsure whether InnerWarden was actually ready.

## Goals
- Keep the setup ultra simple.
- Make automatic changes explicit before applying them.
- Preserve the working Telegram setup flow.
- Leave the user ready to use InnerWarden without needing another command.

## Requirements

### Functional
- R1: Setup must present a short, linear flow with clear steps.
- R2: Safe defaults applied during setup must be shown and confirmed first.
- R3: AI setup must separate `Ollama Local` and `Ollama Cloud`.
- R4: Telegram copy shown by setup must use the `notify telegram` path consistently.
- R5: Setup must show a short review before applying changes.
- R6: Mesh must be opt-in with a clear default of `no`.
- R7: Setup must offer agent connection at the end when supported agents are detected.
- R8: Setup must finish with a validation checklist that says what is ready and what still needs attention.

### UX Constraints
- U1: Avoid deep menus in the common path.
- U2: Do not rewrite the Telegram flow itself inside setup.
- U3: Keep the summary action-oriented and short.

## Success Criteria
- SC1: A first-time user can understand the whole wizard without reading external docs.
- SC2: The setup output makes it obvious whether InnerWarden is ready or not.
- SC3: Users with a running supported AI agent can connect it before setup exits.
