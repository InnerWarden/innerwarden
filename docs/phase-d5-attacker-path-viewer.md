# Phase D5 — Attacker Path Viewer

Status: planned

## Why this phase exists

The current dashboard is already useful for investigation:
- pivoting by `ip`, `user`, and `detector`
- timeline drill-down
- cluster-first workflow
- exportable snapshots
- guarded operator actions

But it still behaves mostly like a technical timeline browser.
An operator can inspect the evidence, yet the dashboard does not clearly answer the higher-level questions fast enough:

- how did the attacker first appear?
- what path did they use?
- did they achieve access?
- did they attempt privilege abuse?
- were they contained?
- what evidence supports each conclusion?

Phase D5 converts the dashboard from a timeline-centric interface into an attacker-path viewer.

## Product goal

Turn one subject investigation into a clear attack story:

1. first signal
2. attack path
3. success or failure
4. privilege or post-access activity
5. containment outcome
6. supporting evidence

The operator should be able to understand the path in under 30 seconds without opening raw JSON first.

## Design goal

The dashboard must visually match the existing InnerWarden site language instead of drifting into a separate product style.

That means:
- same deep navy foundation
- same cyan/teal accent family
- same radial glow / subtle grid atmosphere
- same glassy dark card treatment
- same rounded panel language
- same restrained, high-contrast typography hierarchy

The dashboard should feel like it belongs to the website screenshot and the product brand, not like an unrelated admin panel.

## Non-goals

This phase does not include:
- SSE / push notifications
- multi-host fleet view
- roles / RBAC / session management
- replacing current JSONL contracts
- adding a database

Those remain later phases after the attack-story UX is correct.

## Operator outcomes

After D5, the journey view should answer these explicitly:

- Entry vector:
  - SSH brute-force
  - credential stuffing
  - port scan
  - sudo abuse
  - honeypot follow-up
  - unknown
- Access result:
  - no evidence of success
  - likely success
  - confirmed success
  - inconclusive
- Privilege result:
  - no evidence
  - attempted
  - confirmed
  - inconclusive
- Containment result:
  - blocked
  - monitored only
  - diverted to honeypot
  - still active
  - unknown

## Scope

### D5.1 — Attack Story Builder (backend)

Add a story-derivation layer on top of the current journey assembly.

New derived concepts:
- `JourneyVerdict`
- `JourneyChapter`
- `JourneyStage`
- `EvidenceHighlight`
- `SessionBurst`

The builder should transform raw entries into chapters such as:
- reconnaissance
- initial access attempts
- initial access success
- privilege abuse
- containment
- honeypot interaction
- post-containment activity
- unknown / uncategorized

Expected derivations:
- compact repeated login failures into one burst chapter
- collapse repeated scans into one chapter
- identify first success signal if present
- connect incidents with the events that triggered them
- connect decisions with the incidents they responded to
- connect honeypot evidence after containment / redirection when applicable

`GET /api/journey` should remain the main contract, but be enriched with:
- `verdict`
- `chapters`
- `highlights`
- compacted stage metadata

Raw `entries` stay available for drill-down and export.

### D5.2 — Story-first journey UI

Replace the current “flat timeline first” reading flow with a story-first layout.

Primary journey panel should include:
- top verdict card
- attack path rail / stepper
- chapter cards in chronological order
- evidence highlights per chapter
- raw timeline as secondary expandable layer

Top verdict card should show:
- attacker / subject
- entry vector
- access status
- privilege status
- containment status
- honeypot status
- confidence / certainty language

Attack path rail should show the operator-visible stages, for example:
- signal
- incident
- response
- containment
- honeypot

Chapter card examples:
- `SSH brute-force burst against root/admin/ubuntu`
- `Detector raised ssh_bruteforce incident`
- `AI chose block_ip with 0.96 confidence`
- `Honeypot captured password attempts after redirection`

Each chapter card should expose:
- what happened
- why we believe it happened
- key timestamps
- strongest evidence
- optional raw details toggle

### D5.3 — Evidence presentation and compaction

Raw JSON should stop being the primary detail view.

For each entry kind, render operator-friendly evidence cards first:

- SSH event:
  - username
  - source IP
  - method
  - count / burst context
- Incident:
  - detector
  - threshold reached
  - supporting count / window
- Decision:
  - action type
  - confidence
  - executed vs dry-run
  - execution result
- Honeypot:
  - auth attempts
  - HTTP routes
  - captured credentials
  - banners / bytes / session markers

Raw JSON remains available behind a secondary “technical detail” expansion.

### D5.4 — Visual parity with the site

The attack-story layout must reuse the current site visual system.

Required visual direction:
- deep navy base, not neutral gray
- cyan / teal signal accents, not arbitrary colors
- soft radial ambient lighting behind major panels
- subtle grid / scanline background treatment
- glass-dark cards with distinct borders and elevated states
- consistent border radius with the website
- consistent button, chip, and tag language with the website

Specific dashboard requirements:
- overview and journey should feel like the product marketing site translated into an operator workflow
- investigation cards should remain readable first, stylish second
- severity and outcome colors must remain accessible and semantically stable
- mobile layout must preserve the same brand language, not degrade into generic stacked forms

## API / model expectations

Planned additions to `JourneyResponse`:
- `verdict`
- `chapters`
- `highlights`

Planned example shapes:

```json
{
  "verdict": {
    "entry_vector": "ssh_bruteforce",
    "access_status": "no_evidence_of_success",
    "privilege_status": "no_evidence",
    "containment_status": "blocked",
    "honeypot_status": "engaged",
    "confidence": "medium"
  },
  "chapters": [
    {
      "stage": "initial_access_attempt",
      "title": "SSH brute-force burst",
      "summary": "9 failed password attempts across 3 usernames in 6 minutes.",
      "start_ts": "...",
      "end_ts": "...",
      "evidence_highlights": ["root", "admin", "ubuntu"]
    }
  ]
}
```

This is illustrative only; final field naming may evolve during implementation.

## Acceptance criteria

Phase D5 is done when all of these are true:

1. A user can open one journey and answer, without reading raw JSON first:
   - how the attacker started
   - whether access likely succeeded
   - whether privilege abuse happened
   - whether containment occurred
2. Repeated low-level events are compacted into readable chapters.
3. The top of the journey shows a verdict card instead of only counts and badges.
4. The dashboard looks visually consistent with the current InnerWarden website.
5. Raw forensic detail is still available, but clearly secondary.
6. Existing exports remain available and preserve enough raw context for audits.

## Recommended implementation order

1. backend story derivation and chapter model
2. verdict card + chapter UI
3. evidence cards replacing raw JSON as the default detail layer
4. visual parity pass against the site
5. regression tests for derived story output and chapter grouping

## Deferred after D5

Once D5 is complete, the next dashboard candidates become:
- real-time notification stream (SSE)
- fleet / multi-host view
- stronger access-control layers
- deployment hardening / packaging
