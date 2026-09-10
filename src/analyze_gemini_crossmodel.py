import json
from collections import Counter
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
RESULTS_DIR = PROJECT_ROOT / "results"

DIRECT_FILE = (
    RESULTS_DIR
    / "gemini_crossmodel_direct_rep1_results.jsonl"
)

CANON_FILE = (
    RESULTS_DIR
    / "gemini_crossmodel_canonicalized_rep1_results.jsonl"
)

EXPECTED = 600

TRANSFORMATIONS = [
    "plain",
    "hex",
    "base64",
]


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


def get_success(records):

    success = [
        record
        for record in records
        if record.get("status") == "SUCCESS"
    ]

    # Resume runs may contain failed attempts
    # plus later successful retries.
    latest_success = {}

    for record in success:
        latest_success[
            record["sample_id"]
        ] = record

    return list(
        latest_success.values()
    )


def prediction(record):

    output = record.get(
        "normalized_output"
    )

    if not isinstance(output, dict):
        return None

    value = output.get(
        "classification"
    )

    if isinstance(value, str):
        return value.strip().upper()

    return None


def safe_div(a, b):

    if b == 0:
        return 0.0

    return a / b


def calculate(records, mode="strict"):

    tp = fp = tn = fn = 0

    counts = Counter()

    for record in records:

        truth = record[
            "ground_truth"
        ]

        pred = prediction(
            record
        )

        counts[pred] += 1

        truth_positive = (
            truth == "MALICIOUS"
        )

        if mode == "strict":

            predicted_positive = (
                pred == "MALICIOUS"
            )

        elif mode == "operational":

            predicted_positive = (
                pred in {
                    "MALICIOUS",
                    "SUSPICIOUS",
                }
            )

        else:
            raise ValueError(mode)

        if (
            truth_positive
            and predicted_positive
        ):
            tp += 1

        elif (
            not truth_positive
            and predicted_positive
        ):
            fp += 1

        elif (
            not truth_positive
            and not predicted_positive
        ):
            tn += 1

        else:
            fn += 1

    accuracy = safe_div(
        tp + tn,
        tp + tn + fp + fn
    )

    precision = safe_div(
        tp,
        tp + fp
    )

    recall = safe_div(
        tp,
        tp + fn
    )

    fpr = safe_div(
        fp,
        fp + tn
    )

    fnr = safe_div(
        fn,
        fn + tp
    )

    if precision + recall:

        f1 = (
            2
            * precision
            * recall
            / (
                precision
                + recall
            )
        )

    else:
        f1 = 0.0

    return {
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,

        "accuracy":
            accuracy * 100,

        "precision":
            precision * 100,

        "recall":
            recall * 100,

        "f1":
            f1 * 100,

        "fpr":
            fpr * 100,

        "fnr":
            fnr * 100,

        "prediction_counts":
            dict(counts),
    }


def print_metrics(
    name,
    metrics
):

    print(name)

    print(
        f"Accuracy:  "
        f"{metrics['accuracy']:.2f}%"
    )

    print(
        f"Precision: "
        f"{metrics['precision']:.2f}%"
    )

    print(
        f"Recall:    "
        f"{metrics['recall']:.2f}%"
    )

    print(
        f"F1:        "
        f"{metrics['f1']:.2f}%"
    )

    print(
        f"FPR:       "
        f"{metrics['fpr']:.2f}%"
    )

    print(
        f"FNR:       "
        f"{metrics['fnr']:.2f}%"
    )

    print(
        f"TP={metrics['tp']} "
        f"FP={metrics['fp']} "
        f"TN={metrics['tn']} "
        f"FN={metrics['fn']}"
    )

    print(
        "Predictions:",
        metrics[
            "prediction_counts"
        ]
    )

    print()


def main():

    direct_raw = load_jsonl(
        DIRECT_FILE
    )

    canon_raw = load_jsonl(
        CANON_FILE
    )

    direct = get_success(
        direct_raw
    )

    canon = get_success(
        canon_raw
    )

    print("=" * 78)

    print(
        "AgentShield Cross-Model Validation"
    )

    print(
        "Gemini 2.5 Pro — Analysis"
    )

    print("=" * 78)

    print()

    print(
        f"Direct unique SUCCESS: "
        f"{len(direct)}"
    )

    print(
        f"Canonicalized unique SUCCESS: "
        f"{len(canon)}"
    )

    if (
        len(direct) != EXPECTED
        or len(canon) != EXPECTED
    ):
        raise RuntimeError(
            "Expected 600 successful "
            "samples per pipeline."
        )

    direct_ids = {
        record[
            "sample_id"
        ]
        for record in direct
    }

    canon_ids = {
        record[
            "sample_id"
        ]
        for record in canon
    }

    if direct_ids != canon_ids:
        raise RuntimeError(
            "Direct and canonicalized "
            "sample IDs do not match."
        )

    print()

    # ========================================================
    # Overall strict
    # ========================================================

    print("=" * 78)

    print(
        "STRICT METRICS"
    )

    print("=" * 78)

    print()

    direct_strict = calculate(
        direct,
        "strict"
    )

    canon_strict = calculate(
        canon,
        "strict"
    )

    print_metrics(
        "Gemini Direct",
        direct_strict
    )

    print_metrics(
        "Gemini Canonicalized",
        canon_strict
    )

    print(
        "DELTA — Canonicalized minus Direct"
    )

    print(
        f"Accuracy:  "
        f"{canon_strict['accuracy'] - direct_strict['accuracy']:+.2f} pp"
    )

    print(
        f"Precision: "
        f"{canon_strict['precision'] - direct_strict['precision']:+.2f} pp"
    )

    print(
        f"Recall:    "
        f"{canon_strict['recall'] - direct_strict['recall']:+.2f} pp"
    )

    print(
        f"F1:        "
        f"{canon_strict['f1'] - direct_strict['f1']:+.2f} pp"
    )

    print(
        f"FPR:       "
        f"{canon_strict['fpr'] - direct_strict['fpr']:+.2f} pp"
    )

    print(
        f"FNR:       "
        f"{canon_strict['fnr'] - direct_strict['fnr']:+.2f} pp"
    )

    # ========================================================
    # Operational
    # ========================================================

    print()
    print("=" * 78)

    print(
        "OPERATIONAL METRICS"
    )

    print(
        "SUSPICIOUS + MALICIOUS "
        "treated as positive"
    )

    print("=" * 78)

    print()

    direct_operational = calculate(
        direct,
        "operational"
    )

    canon_operational = calculate(
        canon,
        "operational"
    )

    print_metrics(
        "Gemini Direct",
        direct_operational
    )

    print_metrics(
        "Gemini Canonicalized",
        canon_operational
    )

    print(
        "Operational FPR delta: "
        f"{canon_operational['fpr'] - direct_operational['fpr']:+.2f} pp"
    )

    # ========================================================
    # By transformation
    # ========================================================

    print()
    print("=" * 78)

    print(
        "STRICT METRICS BY TRANSFORMATION"
    )

    print("=" * 78)

    print()

    print(
        f"{'Transform':<12}"
        f"{'Dir FPR':>10}"
        f"{'Can FPR':>10}"
        f"{'Δ FPR':>10}"
        f"{'Dir Rec':>10}"
        f"{'Can Rec':>10}"
        f"{'Δ Rec':>10}"
    )

    print("-" * 72)

    transformation_results = {}

    for transformation in (
        TRANSFORMATIONS
    ):

        direct_subset = [
            record
            for record in direct
            if record[
                "transformation"
            ] == transformation
        ]

        canon_subset = [
            record
            for record in canon
            if record[
                "transformation"
            ] == transformation
        ]

        d = calculate(
            direct_subset,
            "strict"
        )

        c = calculate(
            canon_subset,
            "strict"
        )

        transformation_results[
            transformation
        ] = {
            "direct": d,
            "canonicalized": c,
        }

        print(
            f"{transformation:<12}"
            f"{d['fpr']:>9.1f}%"
            f"{c['fpr']:>9.1f}%"
            f"{c['fpr'] - d['fpr']:>+9.1f}"
            f"{d['recall']:>9.1f}%"
            f"{c['recall']:>9.1f}%"
            f"{c['recall'] - d['recall']:>+9.1f}"
        )

    # ========================================================
    # Operational FPR by transformation
    # ========================================================

    print()
    print("=" * 78)

    print(
        "OPERATIONAL FPR BY TRANSFORMATION"
    )

    print("=" * 78)

    print()

    print(
        f"{'Transform':<12}"
        f"{'Direct':>12}"
        f"{'Canon':>12}"
        f"{'Delta':>12}"
    )

    print("-" * 48)

    for transformation in (
        TRANSFORMATIONS
    ):

        direct_subset = [
            record
            for record in direct
            if record[
                "transformation"
            ] == transformation
        ]

        canon_subset = [
            record
            for record in canon
            if record[
                "transformation"
            ] == transformation
        ]

        d = calculate(
            direct_subset,
            "operational"
        )

        c = calculate(
            canon_subset,
            "operational"
        )

        print(
            f"{transformation:<12}"
            f"{d['fpr']:>11.1f}%"
            f"{c['fpr']:>11.1f}%"
            f"{c['fpr'] - d['fpr']:>+11.1f}"
        )

    # ========================================================
    # Cost
    # ========================================================

    print()
    print("=" * 78)

    print(
        "COST"
    )

    print("=" * 78)

    direct_credits = sum(
        float(
            record.get(
                "used_credits",
                0
            )
            or 0
        )
        for record in direct
    )

    canon_credits = sum(
        float(
            record.get(
                "used_credits",
                0
            )
            or 0
        )
        for record in canon
    )

    print(
        f"Direct total credits: "
        f"{direct_credits:.6f}"
    )

    print(
        f"Canonicalized total credits: "
        f"{canon_credits:.6f}"
    )

    print(
        f"Combined credits: "
        f"{direct_credits + canon_credits:.6f}"
    )

    print(
        f"Direct mean/call: "
        f"{direct_credits / EXPECTED:.6f}"
    )

    print(
        f"Canonicalized mean/call: "
        f"{canon_credits / EXPECTED:.6f}"
    )

    # ========================================================
    # Save
    # ========================================================

    output = {
        "model":
            "Gemini 2.5 Pro",

        "samples_per_pipeline":
            EXPECTED,

        "transformations":
            TRANSFORMATIONS,

        "strict": {
            "direct":
                direct_strict,

            "canonicalized":
                canon_strict,
        },

        "operational": {
            "direct":
                direct_operational,

            "canonicalized":
                canon_operational,
        },

        "by_transformation":
            transformation_results,

        "cost": {
            "direct":
                direct_credits,

            "canonicalized":
                canon_credits,

            "combined":
                direct_credits
                + canon_credits,
        },
    }

    output_path = (
        RESULTS_DIR
        / "gemini_crossmodel_analysis.json"
    )

    with output_path.open(
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            output,
            file,
            ensure_ascii=False,
            indent=2
        )

    print()
    print("=" * 78)

    print(
        "ANALYSIS COMPLETE"
    )

    print("=" * 78)

    print(
        output_path
    )


if __name__ == "__main__":
    main()