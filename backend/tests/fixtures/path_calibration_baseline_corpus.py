"""
Reference corpus that produced path_calibration_baseline.json.

To regenerate the baseline after intentional engine changes:

    cd backend
    python tests/fixtures/path_calibration_baseline_corpus.py > tests/fixtures/path_calibration_baseline.json

Review the diff, confirm the new numbers reflect the intended change,
then commit both this file and the updated JSON together.
"""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from core.calibration_metrics import compute_calibration_metrics

# ── Reference corpus ──────────────────────────────────────────────────────────
# 24 synthetic PathAnalysisFeedback records.
# Each record uses the same field names as the ORM model so it can be passed
# directly to compute_calibration_metrics().
#
# verdict assignment rules used here:
#   correct           — engine prediction matches what a careful analyst would conclude
#   partially_correct — prediction direction is right but confidence or framing is off
#   incorrect         — prediction is wrong or actively misleading

CORPUS = [
    # ── Clean flows — no impairment expected ──────────────────────────────────
    # Full handshake + data observed, no anomalies.
    # confidence ~95–100 (1 visibility note penalty for missing flow record).
    {"predicted_confidence": 95,  "predicted_impairment": None,
     "predicted_outcome": "success",         "verdict": "correct",           "misleading_step": None},
    {"predicted_confidence": 95,  "predicted_impairment": None,
     "predicted_outcome": "success",         "verdict": "correct",           "misleading_step": None},
    {"predicted_confidence": 100, "predicted_impairment": None,
     "predicted_outcome": "success",         "verdict": "correct",           "misleading_step": None},
    # Clean with no port specified: extra visibility note → confidence ~85.
    {"predicted_confidence": 85,  "predicted_impairment": None,
     "predicted_outcome": "success",         "verdict": "correct",           "misleading_step": None},

    # ── backend_response_delay — borderline (200–500 ms) ─────────────────────
    # After recalibration the borderline penalty caps confidence at ~80.
    # Analysts may disagree: the delay is real, but within normal range for
    # many services.  Representative split: 3 correct, 1 partial, 1 incorrect.
    {"predicted_confidence": 80,  "predicted_impairment": "backend_response_delay",
     "predicted_outcome": "success",         "verdict": "correct",           "misleading_step": None},
    {"predicted_confidence": 80,  "predicted_impairment": "backend_response_delay",
     "predicted_outcome": "success",         "verdict": "correct",           "misleading_step": None},
    {"predicted_confidence": 80,  "predicted_impairment": "backend_response_delay",
     "predicted_outcome": "success",         "verdict": "correct",           "misleading_step": None},
    {"predicted_confidence": 80,  "predicted_impairment": "backend_response_delay",
     "predicted_outcome": "success",         "verdict": "partially_correct",
     "misleading_step": (
         "The server response took 310.0 ms after connection \u2014 possible delay, "
         "though this may still be within the normal baseline."
     )},
    {"predicted_confidence": 80,  "predicted_impairment": "backend_response_delay",
     "predicted_outcome": "success",         "verdict": "incorrect",
     "misleading_step": (
         "The server response took 280.0 ms after connection \u2014 possible delay, "
         "though this may still be within the normal baseline."
     )},

    # ── backend_response_delay — clear (>500 ms) ─────────────────────────────
    # Unambiguous slow response; no borderline penalty; confidence ~95.
    {"predicted_confidence": 95,  "predicted_impairment": "backend_response_delay",
     "predicted_outcome": "success",         "verdict": "correct",           "misleading_step": None},
    {"predicted_confidence": 95,  "predicted_impairment": "backend_response_delay",
     "predicted_outcome": "success",         "verdict": "correct",           "misleading_step": None},

    # ── connection_establishment_failure ─────────────────────────────────────
    # SYN with no SYN-ACK returned — unambiguous; confidence ~60 (timing gaps).
    {"predicted_confidence": 60,  "predicted_impairment": "connection_establishment_failure",
     "predicted_outcome": "failure",         "verdict": "correct",           "misleading_step": None},
    {"predicted_confidence": 60,  "predicted_impairment": "connection_establishment_failure",
     "predicted_outcome": "failure",         "verdict": "correct",           "misleading_step": None},
    {"predicted_confidence": 60,  "predicted_impairment": "connection_establishment_failure",
     "predicted_outcome": "failure",         "verdict": "correct",           "misleading_step": None},
    # Server RST observed (firewall_interference is secondary; primary stays
    # connection_establishment_failure due to impairment priority order).
    {"predicted_confidence": 60,  "predicted_impairment": "connection_establishment_failure",
     "predicted_outcome": "failure",         "verdict": "correct",           "misleading_step": None},
    # With a known firewall IP configured: extra visibility notes → conf ~50.
    {"predicted_confidence": 50,  "predicted_impairment": "connection_establishment_failure",
     "predicted_outcome": "failure",         "verdict": "correct",           "misleading_step": None},
    # Mid-stream capture (no SYN visible): outcome=unknown, verdict=partially_correct.
    {"predicted_confidence": 60,  "predicted_impairment": "connection_establishment_failure",
     "predicted_outcome": "unknown",         "verdict": "partially_correct", "misleading_step": None},

    # ── no_server_response ────────────────────────────────────────────────────
    # Handshake completes; no application data follows — reliable signal.
    # confidence ~75–80 (first_response_time_ms penalty).
    {"predicted_confidence": 80,  "predicted_impairment": "no_server_response",
     "predicted_outcome": "failure",         "verdict": "correct",           "misleading_step": None},
    {"predicted_confidence": 80,  "predicted_impairment": "no_server_response",
     "predicted_outcome": "failure",         "verdict": "correct",           "misleading_step": None},
    {"predicted_confidence": 75,  "predicted_impairment": "no_server_response",
     "predicted_outcome": "failure",         "verdict": "correct",           "misleading_step": None},
    {"predicted_confidence": 75,  "predicted_impairment": "no_server_response",
     "predicted_outcome": "failure",         "verdict": "correct",           "misleading_step": None},

    # ── lb_backend_issue ─────────────────────────────────────────────────────
    # LB frontend reachable but no LB→backend flow detected.
    # partially_correct: could be a capture visibility gap on the LB egress.
    {"predicted_confidence": 75,  "predicted_impairment": "lb_backend_issue",
     "predicted_outcome": "failure",         "verdict": "partially_correct",
     "misleading_step": (
         "No LB-to-backend flow was observed \u2014 the load balancer may not have "
         "forwarded traffic to any backend, or this flow may not be visible."
     )},

    # ── return_path_problem ───────────────────────────────────────────────────
    # Sole impairment; confidence ~80 (sole-return-path penalty applied).
    # Analysts often identify this as a capture gap, not a real path failure.
    # Split: 1 partially_correct, 1 incorrect.
    {"predicted_confidence": 80,  "predicted_impairment": "return_path_problem",
     "predicted_outcome": "partial_success", "verdict": "partially_correct",
     "misleading_step": (
         "No return traffic from the load balancer toward the client was detected \u2014 "
         "this may indicate a path interruption or a capture visibility gap at this "
         "monitoring point."
     )},
    {"predicted_confidence": 80,  "predicted_impairment": "return_path_problem",
     "predicted_outcome": "partial_success", "verdict": "incorrect",
     "misleading_step": (
         "No return traffic from the load balancer toward the client was detected \u2014 "
         "this may indicate a path interruption or a capture visibility gap at this "
         "monitoring point."
     )},
]


def _slim(full: dict) -> dict:
    """Keep only the fields required by the baseline spec."""
    return {
        "_meta": {
            "description": "Calibration baseline for CausalPathEngine post-recalibration (2026-04-10).",
            "corpus": (
                f"Synthetic reference corpus of {full['total']} PathAnalysisFeedback records "
                "covering all impairment tokens and confidence bands. Verdicts assigned by "
                "engineering judgment of expected post-recalibration behaviour."
            ),
            "generated_by": "backend/core/calibration_metrics.compute_calibration_metrics",
            "how_to_update": (
                "Re-run the corpus in tests/fixtures/path_calibration_baseline_corpus.py "
                "after intentional engine changes, review diffs, and commit the updated snapshot."
            ),
        },
        "total":                        full["total"],
        "overconfident_incorrect_rate": full["overconfident_incorrect_rate"],
        "underconfident_correct_rate":  full["underconfident_correct_rate"],
        "confidence_bucket_accuracy": [
            {"label": b["label"], "total": b["total"], "accuracy_rate": b["accuracy_rate"]}
            for b in full["confidence_bucket_accuracy"]
        ],
        "impairment_accuracy": [
            {
                "predicted_impairment": i["predicted_impairment"],
                "total":                i["total"],
                "accuracy_rate":        i["accuracy_rate"],
            }
            for i in full["impairment_accuracy"]
        ],
        "misleading_narrative_frequency": full["misleading_narrative_frequency"],
    }


if __name__ == "__main__":
    full    = compute_calibration_metrics(CORPUS)
    slim    = _slim(full)
    print(json.dumps(slim, indent=2, ensure_ascii=False))
