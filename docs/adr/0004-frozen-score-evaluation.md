# ADR 0004 — Judge the strategies on frozen scores, not today's

**Status:** accepted, 2026-08-15

## Context

Ranking today's catalogue with today's EPSS scores against today's KEV membership makes EPSS look
**6.1×** more efficient than CVSS. That comparison is what most public write-ups on this data
report, and it is close to meaningless: EPSS is a model trained on exploitation signals, KEV is the
exploitation ground truth, and the evaluation is therefore scoring a forecaster against data it has
already seen.

FIRST publishes a dated EPSS archive for every day, which makes a real forecast measurable.

## Decision

Report both, in that order, and let the second dismantle the first.

For each of five cutoffs six months apart (2023-08-15 through 2025-08-15):

1. Take the EPSS dump **as published on that date**.
2. Restrict the universe to CVEs **published before** the cutoff and present in that day's dump —
   what a defender could have had on screen that morning.
3. Count as a positive only a CVE that CISA added to KEV **after** the cutoff.
4. Bootstrap a 95 % interval over the positives, 2,000 resamples, seed pinned.

## Consequences

- The finding becomes two-sided and much more interesting than "use EPSS": EPSS still wins at the
  head of the queue (1.2–1.8× the later-exploited caught for the same budget, at every cutoff) but
  **loses on total effort** (it needs more work than CVSS to reach 80 % coverage, ratio 0.5–0.7×,
  at every cutoff).
- Five cutoffs, not one. With 86 to 143 positives per cutoff a single date proves nothing; five
  agreeing dates is the claim.
- One asymmetry survives and is disclosed rather than hidden: **CVSS is read as of today**, because
  the mirror carries no score history. That favours CVSS — and CVSS still loses at the head of the
  queue, so the direction of the result holds despite the handicap.
- Vulnerabilities published after a cutoff are excluded, so this measures backlog triage rather
  than zero-day response. Stated in the README.

## Rejected

**Reporting only the retrospective number.** It is the impressive one and it would have made a
punchier README. It is also the number this project exists to disprove.

**Reporting only the prospective number.** Without the 6.1× to compare against, the honest result
has no context and reads as a weak endorsement of EPSS rather than as a correction.
