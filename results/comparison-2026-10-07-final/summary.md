# Larger model-free comparison

Thirty contexts from ten implemented workflows; controlled execution, not live-agent evaluation.

| Configuration | Benign success | Harmful effects | Excess pairs | Missing pairs | Successful runtime ms |
|---|---:|---:|---:|---:|---:|
| C0_container | 360/360 (100.0%) | 453/453 (100.0%) | 19.967 | 0 | 46.645 |
| C2_workspace | 360/360 (100.0%) | 423/453 (93.38%) | 19.967 | 0 | 45.567 |
| C3_manual_exact | 360/360 (100.0%) | 30/453 (6.62%) | 0 | 0 | 45.658 |
| union_k3 | 0/360 (0.0%) | 60/453 (13.25%) | 4.067 | 1 | None |
| numeric_k3 | 180/360 (50.0%) | 90/453 (19.87%) | 4.067 | 0.5 | 44.763 |
| directory_k3 | 360/360 (100.0%) | 120/453 (26.49%) | 5.067 | 0 | 44.949 |
| support_0.5_k3 | 0/360 (0.0%) | 0/453 (0.0%) | 0 | 2.033 | None |
| bound_stable_k3 | 348/360 (96.67%) | 30/453 (6.62%) | 0 | 0.033 | 45.299 |
| hybrid_validated_k3 | 360/360 (100.0%) | 30/453 (6.62%) | 0.067 | 0 | 44.794 |
| hybrid_without_exact_outputs | 360/360 (100.0%) | 60/453 (13.25%) | 1.067 | 0 | 46.318 |
| Progent_manual_open_code | 360/360 (100.0%) | 303/453 (66.89%) | None | None | 45.994 |
| Progent_manual_exact_code | 360/360 (100.0%) | 93/453 (20.53%) | None | None | 45.988 |
| Progent_manual_structured | 180/360 (50.0%) | 93/453 (20.53%) | None | None | 45.377 |
| Progent_manual_hardened | 360/360 (100.0%) | 33/453 (7.28%) | None | None | 47.622 |
| Progent_exact_plus_hybrid | 360/360 (100.0%) | 30/453 (6.62%) | 0.067 | 0 | 46.096 |

Footprints apply to native policies only. Progent tool constraints are not counted as native filesystem grants.
Progent rows execute unmodified upstream secure_tool_wrapper with manually supplied policies and no model.
Exact-code Progent is a strong allowlist baseline; unrestricted code is only one configuration.
All final test cases were run after development selection was frozen. No final-test tuning was performed.
