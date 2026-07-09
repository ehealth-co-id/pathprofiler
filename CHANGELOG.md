# Changelog

## v0.0.2

- Delete dead `ShouldSwitch` function (replaced by RankByTier).
- Cold probes set `Confidence=0` (underlay taint) so CollapseByNeighbor drops
  them when passive data exists, and RankByTier demotes them.
- Add cold-probe regression tests covering collapse, ranking, and monotonicity.