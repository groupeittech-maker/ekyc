# OCR/MRZ Calibration Report — synthetic tier

**Type** : synthetic-mrz-parser · **seed** : 2026

> **Limitation** : this measures the MRZ parser on synthetically
> corrupted text. It validates logic (check digits, formats, tamper
> detection) — NOT real-camera OCR. Specimens are required for the
> image-level tier.

| Format@Quality | N | Correct | Field err | Missing | False reject | Invalid accept | Tamper catch | Char err |
|---|---|---|---|---|---|---|---|---|
| TD1@q0_clean | 200 | 100.00% | 0.00% | 0.00% | 0.00% | **0.00%** | 100.00% | 0.00% |
| TD1@q1_light | 200 | 57.00% | 8.67% | 3.25% | 2.50% | **0.00%** | 100.00% | 2.07% |
| TD1@q2_degraded | 200 | 8.50% | 25.92% | 10.17% | 11.50% | **0.00%** | 100.00% | 7.47% |
| TD2@q0_clean | 200 | 100.00% | 0.00% | 0.00% | 0.00% | **0.00%** | 100.00% | 0.00% |
| TD2@q1_light | 200 | 55.50% | 8.42% | 3.75% | 1.50% | **0.51%** | 99.49% | 1.85% |
| TD2@q2_degraded | 200 | 7.50% | 29.17% | 10.92% | 5.00% | **1.58%** | 98.42% | 7.50% |
| TD3@q0_clean | 200 | 100.00% | 0.00% | 0.00% | 0.00% | **0.00%** | 100.00% | 0.00% |
| TD3@q1_light | 200 | 57.00% | 8.75% | 3.67% | 0.00% | **0.00%** | 100.00% | 1.98% |
| TD3@q2_degraded | 200 | 9.50% | 30.33% | 11.25% | 0.00% | **0.00%** | 100.00% | 7.57% |

## Reading

- **invalid_accept_rate** = a tampered document that passed — must be 0 %.
- **false_reject_rate** at q2 = expected degradation of a strict parser
  (rejection is recoverable via RETRY — a UX, not security, metric).
- **field_error_rate** at q0 must be 0 % — parser correctness baseline.

## Findings

- **F-C1 — TD2 residual invalid acceptance under noise** : at q2
  ~1.5 % of tampered TD2 MRZs still pass — the TD2 composite check
  covers less of the line than TD3's, so a noise-corrupted digit can
  coincide with a valid check. TD2 borderline parses should route to
  REVIEW rather than auto-accept in production.
- **F-C2 — graceful degradation** : false-reject rises with noise
  (expected for a strict parser) — RETRY budget absorbs it; never
  loosen the parser to lower the rate.
- **F-C3 — synthetic tier only** : no statement about real-camera
  performance can be made until specimen images are measured.