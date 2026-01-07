#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import math
import sys
from decimal import Decimal, ROUND_UP
from typing import Any, Dict, Tuple

METRIC_ORDER = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]

ALLOWED_VALUES = {
    "AV": {"N", "A", "L", "P"},
    "AC": {"L", "H"},
    "PR": {"N", "L", "H"},
    "UI": {"N", "R"},
    "S": {"U", "C"},
    "C": {"N", "L", "H"},
    "I": {"N", "L", "H"},
    "A": {"N", "L", "H"},
}

ALIASES = {
    "AV": {"NETWORK": "N", "ADJACENT": "A", "LOCAL": "L", "PHYSICAL": "P"},
    "AC": {"LOW": "L", "HIGH": "H"},
    "PR": {"NONE": "N", "LOW": "L", "HIGH": "H"},
    "UI": {"NONE": "N", "REQUIRED": "R"},
    "S": {"UNCHANGED": "U", "CHANGED": "C"},
    "C": {"NONE": "N", "LOW": "L", "HIGH": "H"},
    "I": {"NONE": "N", "LOW": "L", "HIGH": "H"},
    "A": {"NONE": "N", "LOW": "L", "HIGH": "H"},
}

WEIGHTS = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "C": {"N": 0.0, "L": 0.22, "H": 0.56},
    "I": {"N": 0.0, "L": 0.22, "H": 0.56},
    "A": {"N": 0.0, "L": 0.22, "H": 0.56},
}

PR_WEIGHTS = {
    "U": {"N": 0.85, "L": 0.62, "H": 0.27},
    "C": {"N": 0.85, "L": 0.68, "H": 0.5},
}


def round_up_1(value: float) -> float:
    return float(Decimal(str(value)).quantize(Decimal("0.1"), rounding=ROUND_UP))


def normalize_metric(metric: str, value: Any) -> str:
    if value is None:
        raise ValueError(f"Missing required metric: {metric}")
    raw = str(value).strip().upper()
    raw = ALIASES.get(metric, {}).get(raw, raw)
    if raw not in ALLOWED_VALUES[metric]:
        allowed = ", ".join(sorted(ALLOWED_VALUES[metric]))
        raise ValueError(f"Invalid {metric} value '{value}'. Allowed: {allowed}.")
    return raw


def load_metrics(data: Dict[str, Any]) -> Dict[str, str]:
    metrics: Dict[str, str] = {}
    for metric in METRIC_ORDER:
        if metric in data:
            metrics[metric] = normalize_metric(metric, data[metric])
        else:
            key_lower = metric.lower()
            if key_lower in data:
                metrics[metric] = normalize_metric(metric, data[key_lower])
    missing = [m for m in METRIC_ORDER if m not in metrics]
    if missing:
        raise ValueError(f"Missing metrics: {', '.join(missing)}")
    return metrics


def compute_base_score(metrics: Dict[str, str]) -> Tuple[float, float, float]:
    scope = metrics["S"]

    iss = 1 - (1 - WEIGHTS["C"][metrics["C"]]) * (1 - WEIGHTS["I"][metrics["I"]]) * (1 - WEIGHTS["A"][metrics["A"]])
    if scope == "U":
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * math.pow(iss - 0.02, 15)

    impact = max(impact, 0.0)

    exploitability = 8.22 * WEIGHTS["AV"][metrics["AV"]] * WEIGHTS["AC"][metrics["AC"]] * PR_WEIGHTS[scope][metrics["PR"]] * WEIGHTS["UI"][metrics["UI"]]

    if impact <= 0:
        return 0.0, impact, exploitability

    if scope == "U":
        base = min(impact + exploitability, 10.0)
    else:
        base = min(1.08 * (impact + exploitability), 10.0)

    return round_up_1(base), impact, exploitability


def severity_label(score: float) -> str:
    if score == 0.0:
        return "None"
    if score <= 3.9:
        return "Low"
    if score <= 6.9:
        return "Medium"
    if score <= 8.9:
        return "High"
    return "Critical"


def build_vector(metrics: Dict[str, str]) -> str:
    parts = ["CVSS:3.1"] + [f"{m}:{metrics[m]}" for m in METRIC_ORDER]
    return "/".join(parts)


def main() -> int:
    ap = argparse.ArgumentParser(description="Calculate CVSS v3.1 base score from JSON metrics.")
    ap.add_argument("-i", "--input", help="Path to JSON file. If omitted, read from stdin.")
    args = ap.parse_args()

    if args.input:
        with open(args.input, "r", encoding="utf-8") as f:
            data = json.load(f)
    else:
        data = json.load(sys.stdin)

    if not isinstance(data, dict):
        raise SystemExit("Input JSON must be an object with CVSS metrics.")

    version = str(data.get("version", "3.1")).strip()
    if version != "3.1":
        raise SystemExit(f"Unsupported CVSS version: {version}. Only 3.1 is supported.")

    metrics = load_metrics(data)
    base_score, impact, exploitability = compute_base_score(metrics)
    vector = build_vector(metrics)

    result = {
        "version": "3.1",
        "vector": vector,
        "base_score": base_score,
        "severity": severity_label(base_score),
        "impact_subscore": round(impact, 2),
        "exploitability_subscore": round(exploitability, 2),
        "metrics": metrics,
    }

    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
