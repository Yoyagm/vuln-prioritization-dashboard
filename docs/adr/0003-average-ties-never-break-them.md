# ADR 0003 — Average tied scores; never let a sort break them

**Status:** accepted, 2026-08-15

## Context

The project's central measurement is a coverage curve: work down a ranked list of vulnerabilities
and count how many of the confirmed-exploited ones you have covered after N patches.

CVSS is a coarse scale. **47,253 CVEs sit at 9.0 or above and tens of thousands share a base score
of exactly 9.8.** So for most of the CVSS curve, the question "which CVE comes next?" is not
answered by the metric at all — it is answered by whatever the sort does with equal keys.

`numpy.argsort(kind="stable")` and `DataFrame.sort_values` both resolve ties by original row order,
which in this dataset is CVE identifier order, which is chronological. A curve built that way is
partly a measurement of **CVE numbering**, and it would move if the input were shuffled.

## Decision

Treat each block of equal scores as its expected value under uniformly random ordering within the
block. Concretely: evaluate the curve only at block boundaries — one block per distinct score — and
read it linearly in between, since a block of `n` items holding `p` positives yields `p·k/n`
positives in expectation after taking `k` of them.

Missing scores form their own block, sorted last, for every strategy alike.

## Consequences

- The answer no longer depends on input order. Shuffling the rows leaves every published figure
  unchanged.
- It is also the *fair* reading: a defender working a 30,000-CVE tie has no reason to pick the
  exploited ones first, and no reason to pick them last.
- The curve is cheaper to store: one point per distinct score rather than one per CVE.
- The implementation is subtle enough to be worth guarding, so `tests/test_metrics.py` pins it with
  a hand-computable fixture **and a negative control** — a test that runs the naive implementation
  on the same fixture and asserts it gives a different, wrong answer. Without that control the
  guard could silently stop testing anything.

## Rejected

**Optimistic or pessimistic tie-breaking** (exploited first, or last). Both are defensible as
bounds, and both were rejected as the headline because each is a best or worst case rather than an
expectation, and the gap between them on this data is enormous.

**Reporting the bound as a band.** More honest still, and worth revisiting — but it doubles every
curve and complicates the one chart the whole project rests on, for a result whose direction the
bands do not change.
