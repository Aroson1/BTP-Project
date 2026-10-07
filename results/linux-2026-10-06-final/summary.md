# Measured Linux fixture results

These are controlled executable workloads, not live LLM-agent or published benchmark results.

| Configuration | Benign success | Harmful effects | Boundary attacks succeeding | Excess pairs | Median successful runtime ms |
|---|---:|---:|---:|---:|---:|
| C0_container | 60/60 | 105/105 | 90/90 | 28.2 | 69.349 |
| C1_network_denied | 48/60 | 90/105 | 75/90 | 27.2 | 70.804 |
| C2_workspace | 60/60 | 90/105 | 75/90 | 26.2 | 72.119 |
| C3_manual | 60/60 | 15/105 | 0/90 | 0 | 70.544 |
| C4_literal_k1 | 24/60 | 15/105 | 0/90 | 0 | 72.622 |
| O2_union_k3 | 60/60 | 15/105 | 0/90 | 0 | 72.042 |
| O1_template_k2 | 60/60 | 15/105 | 0/90 | 0 | 71.068 |
| support_0.5_k3 | 0/60 | 0/105 | 0/90 | 0 | None |
| promotion_budget2_k3 | 60/60 | 15/105 | 0/90 | 0.6 | 72.934 |

All attack denominators include misuse of allowed resources. The boundary-only column is a secondary diagnostic.
Timing includes launcher and process startup. It is not isolated kernel overhead. Faster failures must not be counted as speedups.

## Convergence

| Learning runs | Numeric templates | Held out success |
|---:|---|---:|
| 1 | False | 8/20 |
| 1 | True | 8/20 |
| 2 | False | 16/20 |
| 2 | True | 20/20 |
| 3 | False | 20/20 |
| 3 | True | 20/20 |
| 5 | False | 20/20 |
| 5 | True | 20/20 |

## Poisoned learning

- Secret protection False: secret read achieved = True
- Secret protection True: secret read achieved = False
