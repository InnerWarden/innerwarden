# Feature: Setup Zero Friction (Day-0 Ready)

## Origin
Product direction for basic users: after `innerwarden setup`, the system should be usable immediately without additional commands, and agent integration should be simple and explicit.

## Problem
Even with the current improved setup, users can still feel uncertain about "what is ready", and agent connection still has perceived friction for non-technical operators.

## Goals
- Make setup completion equal to operational readiness for common paths.
- Reduce mental load for basic users to a few explicit choices.
- Connect supported local agents in-setup via selection list (no PID hunt in default path).
- Keep Telegram flow unchanged (already validated in production UX).

## Requirements

### Functional
- R1: Setup must expose two modes: `basic` and `advanced`.
- R2: `basic` mode must complete in <= 4 decisions for default path.
- R3: Setup must auto-detect supported running agents and show multi-select (`1,3,all`) inside setup.
- R4: If exactly one supported agent is detected, setup must offer one-confirm connect.
- R5: Setup must apply all selected changes in one transaction and restart services once.
- R6: Setup final screen must show readiness verdict: `READY` or `READY_WITH_GAPS`.
- R7: For `READY_WITH_GAPS`, setup must print one single command to close critical gaps.
- R8: Setup must keep Telegram helper untouched and only orchestrate when to call it.

### UX Constraints
- U1: Every step must answer "what is happening now" and "what changes will be applied".
- U2: No requirement to manually find PID in basic flow.
- U3: Avoid dense output; short, action-first copy.

## Success Criteria
- SC1: New user reaches `READY` in one setup pass on clean install.
- SC2: Agent connection success rate increases vs current baseline.
- SC3: Reduction in post-setup support questions about "next command".
