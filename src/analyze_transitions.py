import csv
import json
from collections import Counter, defaultdict
from pathlib import Path


# ============================================================
# Paths
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parent.parent

RESULTS_DIR = PROJECT_ROOT / "results"

V1_FILE = RESULTS_DIR / "v1_official_results.jsonl"
V2_FILE = RESULTS_DIR / "v2_official_results.jsonl"

OUTPUT_CSV = RESULTS_DIR / "v1_v2_transitions.csv"
OUTPUT_JSON = RESULTS_DIR / "v1_v2_transitions_summary.json"


# ============================================================
# Loaders
# ============================================================

def load_jsonl(path):
    records = []

    with path.open(
        "r",
        encoding="utf-8"
    ) as file:

        for line in file:

            line = line.strip()

            if line:
                records.append(
                    json.loads(line)
                )

    return records


def latest_success_by_id(records):

    result = {}

    for record in records:

        if record.get("status") == "SUCCESS":

            result[
                record["sample_id"]
            ] = record

    return result


# ============================================================
# Field helpers
# ============================================================

def get_prediction(record):

    prediction = (
        record
        .get(
            "normalized_output",
            {}
        )
        .get(
            "classification"
        )
    )

    if isinstance(prediction, str):

        prediction = (
            prediction
            .strip()
            .upper()
        )

    return prediction


def get_risk(record):

    return (
        record
        .get(
            "normalized_output",
            {}
        )
        .get(
            "risk_score"
        )
    )


def get_truth(record):

    truth = (
        record.get("ground_truth")
        or record.get("label")
    )

    if isinstance(truth, str):

        truth = (
            truth
            .strip()
            .upper()
        )

    return truth


# ============================================================
# Improvement scoring
# ============================================================

def prediction_score(
    ground_truth,
    prediction
):
    """
    Score how close the prediction is
    to the binary ground truth.

    SAFE ground truth:
        SAFE        = 2
        SUSPICIOUS  = 1
        MALICIOUS   = 0

    MALICIOUS ground truth:
        MALICIOUS   = 2
        SUSPICIOUS  = 1
        SAFE        = 0
    """

    if ground_truth == "SAFE":

        scores = {
            "SAFE": 2,
            "SUSPICIOUS": 1,
            "MALICIOUS": 0,
        }

    elif ground_truth == "MALICIOUS":

        scores = {
            "MALICIOUS": 2,
            "SUSPICIOUS": 1,
            "SAFE": 0,
        }

    else:

        return None


    return scores.get(
        prediction
    )


def classify_change(
    ground_truth,
    v1_prediction,
    v2_prediction
):

    v1_score = prediction_score(
        ground_truth,
        v1_prediction
    )

    v2_score = prediction_score(
        ground_truth,
        v2_prediction
    )


    if (
        v1_score is None
        or v2_score is None
    ):

        return "UNKNOWN"


    if v2_score > v1_score:
        return "IMPROVED"

    if v2_score < v1_score:
        return "WORSENED"

    return "UNCHANGED"


# ============================================================
# Main
# ============================================================

def main():

    v1_records = load_jsonl(
        V1_FILE
    )

    v2_records = load_jsonl(
        V2_FILE
    )


    v1 = latest_success_by_id(
        v1_records
    )

    v2 = latest_success_by_id(
        v2_records
    )


    v1_ids = set(v1)
    v2_ids = set(v2)


    if v1_ids != v2_ids:

        raise RuntimeError(
            "V1 and V2 sample IDs do not match."
        )


    print(
        f"Paired samples: "
        f"{len(v1_ids)}"
    )


    rows = []

    overall_changes = Counter()

    by_transformation = defaultdict(
        Counter
    )

    safe_changes = Counter()

    malicious_changes = Counter()

    transition_counts = Counter()


    for sample_id in sorted(
        v1_ids
    ):

        v1_record = v1[
            sample_id
        ]

        v2_record = v2[
            sample_id
        ]


        truth = get_truth(
            v1_record
        )

        transformation = (
            v1_record[
                "transformation"
            ]
        )


        v1_prediction = get_prediction(
            v1_record
        )

        v2_prediction = get_prediction(
            v2_record
        )


        change = classify_change(
            truth,
            v1_prediction,
            v2_prediction
        )


        transition = (
            f"{v1_prediction}"
            f" -> "
            f"{v2_prediction}"
        )


        overall_changes[
            change
        ] += 1


        by_transformation[
            transformation
        ][
            change
        ] += 1


        transition_counts[
            transition
        ] += 1


        if truth == "SAFE":

            safe_changes[
                change
            ] += 1

        elif truth == "MALICIOUS":

            malicious_changes[
                change
            ] += 1


        v1_risk = get_risk(
            v1_record
        )

        v2_risk = get_risk(
            v2_record
        )


        if (
            isinstance(
                v1_risk,
                (int, float)
            )
            and isinstance(
                v2_risk,
                (int, float)
            )
        ):

            risk_delta = (
                v2_risk
                - v1_risk
            )

        else:

            risk_delta = None


        row = {

            "sample_id":
                sample_id,

            "base_id":
                v1_record[
                    "base_id"
                ],

            "ground_truth":
                truth,

            "category":
                v1_record[
                    "category"
                ],

            "transformation":
                transformation,

            "v1_prediction":
                v1_prediction,

            "v2_prediction":
                v2_prediction,

            "transition":
                transition,

            "change":
                change,

            "v1_risk":
                v1_risk,

            "v2_risk":
                v2_risk,

            "risk_delta":
                risk_delta,

            "canonicalization_changed":
                v2_record.get(
                    "canonicalization_changed"
                ),

            "detected_representation":
                v2_record.get(
                    "detected_representation"
                ),

            "original_input":
                v2_record.get(
                    "original_input"
                ),

            "canonical_input":
                v2_record.get(
                    "canonical_input"
                ),
        }


        rows.append(
            row
        )


    # ========================================================
    # Save detailed CSV
    # ========================================================

    fields = [
        "sample_id",
        "base_id",
        "ground_truth",
        "category",
        "transformation",
        "v1_prediction",
        "v2_prediction",
        "transition",
        "change",
        "v1_risk",
        "v2_risk",
        "risk_delta",
        "canonicalization_changed",
        "detected_representation",
        "original_input",
        "canonical_input",
    ]


    with OUTPUT_CSV.open(
        "w",
        newline="",
        encoding="utf-8"
    ) as file:

        writer = csv.DictWriter(
            file,
            fieldnames=fields
        )

        writer.writeheader()

        writer.writerows(
            rows
        )


    # ========================================================
    # Save summary JSON
    # ========================================================

    summary = {

        "paired_samples":
            len(rows),

        "overall_changes":
            dict(
                overall_changes
            ),

        "safe_changes":
            dict(
                safe_changes
            ),

        "malicious_changes":
            dict(
                malicious_changes
            ),

        "transition_counts":
            dict(
                transition_counts
            ),

        "by_transformation": {
            name: dict(counts)
            for name, counts
            in sorted(
                by_transformation.items()
            )
        }
    }


    with OUTPUT_JSON.open(
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            summary,
            file,
            ensure_ascii=False,
            indent=2
        )


    # ========================================================
    # Console output
    # ========================================================

    print()
    print(
        "=" * 70
    )

    print(
        "OVERALL PAIRED CHANGES"
    )

    print(
        "=" * 70
    )


    for name in [
        "IMPROVED",
        "UNCHANGED",
        "WORSENED"
    ]:

        print(
            f"{name:<12}: "
            f"{overall_changes[name]}"
        )


    print()
    print(
        "SAFE samples:"
    )

    for name in [
        "IMPROVED",
        "UNCHANGED",
        "WORSENED"
    ]:

        print(
            f"  {name:<10}: "
            f"{safe_changes[name]}"
        )


    print()
    print(
        "MALICIOUS samples:"
    )

    for name in [
        "IMPROVED",
        "UNCHANGED",
        "WORSENED"
    ]:

        print(
            f"  {name:<10}: "
            f"{malicious_changes[name]}"
        )


    print()
    print(
        "=" * 70
    )

    print(
        "CHANGES BY TRANSFORMATION"
    )

    print(
        "=" * 70
    )


    print(
        f"{'Transformation':<18}"
        f"{'Improved':>12}"
        f"{'Unchanged':>12}"
        f"{'Worsened':>12}"
    )

    print(
        "-" * 54
    )


    for transformation in sorted(
        by_transformation
    ):

        counts = (
            by_transformation[
                transformation
            ]
        )

        print(
            f"{transformation:<18}"
            f"{counts['IMPROVED']:>12}"
            f"{counts['UNCHANGED']:>12}"
            f"{counts['WORSENED']:>12}"
        )


    print()
    print(
        "=" * 70
    )

    print(
        "PREDICTION TRANSITIONS"
    )

    print(
        "=" * 70
    )


    for transition, count in (
        transition_counts
        .most_common()
    ):

        print(
            f"{transition:<28}"
            f"{count:>5}"
        )


    # ========================================================
    # Important SAFE corrections
    # ========================================================

    print()
    print(
        "=" * 70
    )

    print(
        "SAFE SAMPLES IMPROVED IN V2"
    )

    print(
        "=" * 70
    )


    improved_safe_rows = [

        row
        for row in rows

        if (
            row[
                "ground_truth"
            ] == "SAFE"

            and row[
                "change"
            ] == "IMPROVED"
        )
    ]


    for row in improved_safe_rows:

        print(
            f"{row['sample_id']:<24}"
            f"{row['v1_prediction']:<12}"
            f"-> "
            f"{row['v2_prediction']:<12}"
            f" | "
            f"{row['transformation']}"
        )


    print()
    print(
        "Detailed CSV saved to:"
    )

    print(
        OUTPUT_CSV
    )


    print()
    print(
        "Summary JSON saved to:"
    )

    print(
        OUTPUT_JSON
    )


if __name__ == "__main__":
    main()