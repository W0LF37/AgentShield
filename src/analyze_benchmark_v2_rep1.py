import csv
import json
from collections import Counter
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent

RESULTS_DIR = PROJECT_ROOT / "results"

V1_FILE = (
    RESULTS_DIR
    / "benchmark_v2_v1_rep1_results.jsonl"
)

V2_FILE = (
    RESULTS_DIR
    / "benchmark_v2_v2_rep1_results.jsonl"
)

OUTPUT_JSON = (
    RESULTS_DIR
    / "benchmark_v2_rep1_analysis.json"
)

OUTPUT_TRANSFORM_CSV = (
    RESULTS_DIR
    / "benchmark_v2_rep1_by_transformation.csv"
)

OUTPUT_CATEGORY_CSV = (
    RESULTS_DIR
    / "benchmark_v2_rep1_by_category.csv"
)


EXPECTED_SAMPLES = 500

ALLOWED_PREDICTIONS = {
    "SAFE",
    "SUSPICIOUS",
    "MALICIOUS",
}


# ============================================================
# Helpers
# ============================================================

def load_jsonl(path):

    records = []

    with path.open(
        "r",
        encoding="utf-8"
    ) as file:

        for line_number, line in enumerate(
            file,
            start=1
        ):

            line = line.strip()

            if not line:
                continue

            try:
                records.append(
                    json.loads(line)
                )

            except json.JSONDecodeError as error:
                raise RuntimeError(
                    f"Invalid JSON in {path.name} "
                    f"line {line_number}: {error}"
                )

    return records


def prediction(record):

    output = record.get(
        "normalized_output",
        {}
    )

    pred = output.get(
        "classification"
    )

    if isinstance(pred, str):
        pred = pred.strip().upper()

    return pred


def safe_divide(a, b):

    if b == 0:
        return 0.0

    return a / b


def percent(value):

    return value * 100.0


def numeric_sum(records, field):

    values = []

    for record in records:

        value = record.get(field)

        if isinstance(
            value,
            (int, float)
        ):
            values.append(
                float(value)
            )

    return sum(values)


def numeric_mean(records, field):

    values = []

    for record in records:

        value = record.get(field)

        if isinstance(
            value,
            (int, float)
        ):
            values.append(
                float(value)
            )

    if not values:
        return None

    return sum(values) / len(values)


# ============================================================
# Validation
# ============================================================

def validate_records(
    records,
    pipeline
):

    success = [
        r
        for r in records
        if r.get("status") == "SUCCESS"
    ]

    if len(success) != EXPECTED_SAMPLES:

        raise RuntimeError(
            f"{pipeline}: expected "
            f"{EXPECTED_SAMPLES} SUCCESS records, "
            f"found {len(success)}."
        )


    sample_ids = [
        r.get("sample_id")
        for r in success
    ]

    if len(
        set(sample_ids)
    ) != EXPECTED_SAMPLES:

        raise RuntimeError(
            f"{pipeline}: sample IDs "
            "are not unique."
        )


    predictions = Counter(
        prediction(r)
        for r in success
    )


    invalid_predictions = [
        pred
        for pred in predictions
        if pred not in ALLOWED_PREDICTIONS
    ]


    if invalid_predictions:

        raise RuntimeError(
            f"{pipeline}: invalid predictions: "
            f"{invalid_predictions}"
        )


    hashes = {
        r.get("benchmark_sha256")
        for r in success
    }


    if len(hashes) != 1:

        raise RuntimeError(
            f"{pipeline}: inconsistent "
            "benchmark SHA256 values."
        )


    return success


# ============================================================
# Metrics
# ============================================================

def calculate_metrics(
    records,
    mode="strict"
):

    tp = 0
    fp = 0
    tn = 0
    fn = 0

    exact_correct = 0

    prediction_counts = Counter()


    for record in records:

        truth = record[
            "ground_truth"
        ]

        pred = prediction(
            record
        )


        prediction_counts[
            pred
        ] += 1


        if pred == truth:
            exact_correct += 1


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

            raise ValueError(
                f"Unknown metric mode: {mode}"
            )


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

        elif (
            truth_positive
            and not predicted_positive
        ):
            fn += 1


    accuracy = safe_divide(
        tp + tn,
        tp + fp + tn + fn
    )

    precision = safe_divide(
        tp,
        tp + fp
    )

    recall = safe_divide(
        tp,
        tp + fn
    )

    specificity = safe_divide(
        tn,
        tn + fp
    )

    fpr = safe_divide(
        fp,
        fp + tn
    )

    fnr = safe_divide(
        fn,
        fn + tp
    )


    if precision + recall == 0:

        f1 = 0.0

    else:

        f1 = (
            2
            * precision
            * recall
            / (
                precision
                + recall
            )
        )


    exact_accuracy = safe_divide(
        exact_correct,
        len(records)
    )


    return {
        "n":
            len(records),

        "tp":
            tp,

        "fp":
            fp,

        "tn":
            tn,

        "fn":
            fn,

        "accuracy":
            percent(accuracy),

        "precision":
            percent(precision),

        "recall":
            percent(recall),

        "f1":
            percent(f1),

        "specificity":
            percent(specificity),

        "fpr":
            percent(fpr),

        "fnr":
            percent(fnr),

        "exact_accuracy":
            percent(exact_accuracy),

        "prediction_counts":
            dict(prediction_counts),
    }


# ============================================================
# Per-transform analysis
# ============================================================

def transform_analysis(
    v1_records,
    v2_records
):

    transformations = sorted({
        r[
            "transformation"
        ]
        for r in v1_records
    })


    rows = []


    for transformation in transformations:

        v1_subset = [
            r
            for r in v1_records
            if (
                r["transformation"]
                == transformation
            )
        ]

        v2_subset = [
            r
            for r in v2_records
            if (
                r["transformation"]
                == transformation
            )
        ]


        v1_strict = calculate_metrics(
            v1_subset,
            "strict"
        )

        v2_strict = calculate_metrics(
            v2_subset,
            "strict"
        )


        v1_operational = calculate_metrics(
            v1_subset,
            "operational"
        )

        v2_operational = calculate_metrics(
            v2_subset,
            "operational"
        )


        rows.append({
            "transformation":
                transformation,

            "n":
                len(v1_subset),

            "v1_strict_fpr":
                v1_strict["fpr"],

            "v2_strict_fpr":
                v2_strict["fpr"],

            "strict_fpr_delta_pp":
                (
                    v2_strict["fpr"]
                    - v1_strict["fpr"]
                ),

            "v1_operational_fpr":
                v1_operational["fpr"],

            "v2_operational_fpr":
                v2_operational["fpr"],

            "operational_fpr_delta_pp":
                (
                    v2_operational["fpr"]
                    - v1_operational["fpr"]
                ),

            "v1_strict_recall":
                v1_strict["recall"],

            "v2_strict_recall":
                v2_strict["recall"],

            "strict_recall_delta_pp":
                (
                    v2_strict["recall"]
                    - v1_strict["recall"]
                ),

            "v1_fp":
                v1_strict["fp"],

            "v2_fp":
                v2_strict["fp"],

            "v1_fn":
                v1_strict["fn"],

            "v2_fn":
                v2_strict["fn"],
        })


    return rows


# ============================================================
# Per-category analysis
# ============================================================

def category_analysis(
    v1_records,
    v2_records
):

    categories = sorted({
        r[
            "category"
        ]
        for r in v1_records
    })


    rows = []


    for category in categories:

        v1_subset = [
            r
            for r in v1_records
            if r["category"] == category
        ]

        v2_subset = [
            r
            for r in v2_records
            if r["category"] == category
        ]


        labels = {
            r[
                "ground_truth"
            ]
            for r in v1_subset
        }


        if len(labels) != 1:

            raise RuntimeError(
                f"Category {category} contains "
                "mixed ground-truth labels."
            )


        ground_truth = next(
            iter(labels)
        )


        v1_metrics = calculate_metrics(
            v1_subset,
            "strict"
        )

        v2_metrics = calculate_metrics(
            v2_subset,
            "strict"
        )


        row = {
            "category":
                category,

            "ground_truth":
                ground_truth,

            "n":
                len(v1_subset),

            "v1_fp":
                v1_metrics["fp"],

            "v2_fp":
                v2_metrics["fp"],

            "v1_fn":
                v1_metrics["fn"],

            "v2_fn":
                v2_metrics["fn"],
        }


        if ground_truth == "SAFE":

            row[
                "v1_primary_rate"
            ] = v1_metrics["fpr"]

            row[
                "v2_primary_rate"
            ] = v2_metrics["fpr"]

            row[
                "metric"
            ] = "FPR"

        else:

            row[
                "v1_primary_rate"
            ] = v1_metrics["recall"]

            row[
                "v2_primary_rate"
            ] = v2_metrics["recall"]

            row[
                "metric"
            ] = "Recall"


        row[
            "delta_pp"
        ] = (
            row["v2_primary_rate"]
            - row["v1_primary_rate"]
        )


        rows.append(
            row
        )


    return rows


# ============================================================
# Paired analysis
# ============================================================

def paired_analysis(
    v1_records,
    v2_records
):

    v1_map = {
        r["sample_id"]: r
        for r in v1_records
    }

    v2_map = {
        r["sample_id"]: r
        for r in v2_records
    }


    if (
        set(v1_map)
        != set(v2_map)
    ):

        raise RuntimeError(
            "V1 and V2 sample IDs do not match."
        )


    transition_counts = Counter()


    safe_improved = 0
    safe_worsened = 0
    safe_unchanged = 0


    malicious_improved = 0
    malicious_worsened = 0
    malicious_unchanged = 0


    safe_by_transform = {}


    transformations = sorted({
        r["transformation"]
        for r in v1_records
    })


    for transformation in transformations:

        safe_by_transform[
            transformation
        ] = {
            "improved": 0,
            "worsened": 0,
            "unchanged": 0,
        }


    for sample_id in sorted(
        v1_map
    ):

        r1 = v1_map[
            sample_id
        ]

        r2 = v2_map[
            sample_id
        ]


        truth = r1[
            "ground_truth"
        ]

        p1 = prediction(
            r1
        )

        p2 = prediction(
            r2
        )


        transition_counts[
            f"{p1}->{p2}"
        ] += 1


        if truth == "SAFE":

            v1_fp = (
                p1 == "MALICIOUS"
            )

            v2_fp = (
                p2 == "MALICIOUS"
            )


            transform = r1[
                "transformation"
            ]


            if (
                v1_fp
                and not v2_fp
            ):

                safe_improved += 1

                safe_by_transform[
                    transform
                ][
                    "improved"
                ] += 1


            elif (
                not v1_fp
                and v2_fp
            ):

                safe_worsened += 1

                safe_by_transform[
                    transform
                ][
                    "worsened"
                ] += 1


            else:

                safe_unchanged += 1

                safe_by_transform[
                    transform
                ][
                    "unchanged"
                ] += 1


        else:

            v1_correct = (
                p1 == "MALICIOUS"
            )

            v2_correct = (
                p2 == "MALICIOUS"
            )


            if (
                not v1_correct
                and v2_correct
            ):

                malicious_improved += 1


            elif (
                v1_correct
                and not v2_correct
            ):

                malicious_worsened += 1


            else:

                malicious_unchanged += 1


    return {
        "prediction_transitions":
            dict(
                transition_counts
            ),

        "safe_strict_fp_changes": {
            "improved":
                safe_improved,

            "worsened":
                safe_worsened,

            "unchanged":
                safe_unchanged,
        },

        "malicious_strict_detection_changes": {
            "improved":
                malicious_improved,

            "worsened":
                malicious_worsened,

            "unchanged":
                malicious_unchanged,
        },

        "safe_by_transformation":
            safe_by_transform,
    }


# ============================================================
# CSV writers
# ============================================================

def write_csv(
    path,
    rows
):

    if not rows:
        return


    fieldnames = list(
        rows[0].keys()
    )


    with path.open(
        "w",
        newline="",
        encoding="utf-8"
    ) as file:

        writer = csv.DictWriter(
            file,
            fieldnames=fieldnames
        )

        writer.writeheader()

        writer.writerows(
            rows
        )


# ============================================================
# Pretty printer
# ============================================================

def print_metrics(
    name,
    metrics
):

    print(
        name
    )

    print(
        "-" * 72
    )

    print(
        f"Accuracy:  "
        f"{metrics['accuracy']:.1f}%"
    )

    print(
        f"Precision: "
        f"{metrics['precision']:.1f}%"
    )

    print(
        f"Recall:    "
        f"{metrics['recall']:.1f}%"
    )

    print(
        f"F1:        "
        f"{metrics['f1']:.1f}%"
    )

    print(
        f"FPR:       "
        f"{metrics['fpr']:.1f}%"
    )

    print(
        f"FNR:       "
        f"{metrics['fnr']:.1f}%"
    )

    print(
        f"TP={metrics['tp']}  "
        f"FP={metrics['fp']}  "
        f"TN={metrics['tn']}  "
        f"FN={metrics['fn']}"
    )

    print()


# ============================================================
# Main
# ============================================================

def main():

    print(
        "=" * 72
    )

    print(
        "AgentShield-ObfusBench"
    )

    print(
        "Benchmark v2 — Replicate 1 Analysis"
    )

    print(
        "=" * 72
    )

    print()


    v1_raw = load_jsonl(
        V1_FILE
    )

    v2_raw = load_jsonl(
        V2_FILE
    )


    v1 = validate_records(
        v1_raw,
        "V1"
    )

    v2 = validate_records(
        v2_raw,
        "V2"
    )


    v1_hash = next(iter({
        r["benchmark_sha256"]
        for r in v1
    }))

    v2_hash = next(iter({
        r["benchmark_sha256"]
        for r in v2
    }))


    if v1_hash != v2_hash:

        raise RuntimeError(
            "V1 and V2 used different "
            "benchmark hashes."
        )


    v1_ids = {
        r["sample_id"]
        for r in v1
    }

    v2_ids = {
        r["sample_id"]
        for r in v2
    }


    if v1_ids != v2_ids:

        raise RuntimeError(
            "V1 and V2 sample sets differ."
        )


    print(
        f"V1 SUCCESS: {len(v1)}"
    )

    print(
        f"V2 SUCCESS: {len(v2)}"
    )

    print(
        f"Paired samples: "
        f"{len(v1_ids)}"
    )

    print(
        f"Benchmark SHA256:"
    )

    print(
        v1_hash
    )

    print()


    # ========================================================
    # Overall metrics
    # ========================================================

    v1_strict = calculate_metrics(
        v1,
        "strict"
    )

    v2_strict = calculate_metrics(
        v2,
        "strict"
    )

    v1_operational = calculate_metrics(
        v1,
        "operational"
    )

    v2_operational = calculate_metrics(
        v2,
        "operational"
    )


    print(
        "=" * 72
    )

    print(
        "PRIMARY METRICS — STRICT"
    )

    print(
        "=" * 72
    )

    print_metrics(
        "V1 DIRECT",
        v1_strict
    )

    print_metrics(
        "V2 CANONICALIZED",
        v2_strict
    )


    print(
        "STRICT DELTA — V2 minus V1"
    )

    print(
        "-" * 72
    )

    print(
        f"Accuracy:  "
        f"{v2_strict['accuracy'] - v1_strict['accuracy']:+.1f} pp"
    )

    print(
        f"Precision: "
        f"{v2_strict['precision'] - v1_strict['precision']:+.1f} pp"
    )

    print(
        f"Recall:    "
        f"{v2_strict['recall'] - v1_strict['recall']:+.1f} pp"
    )

    print(
        f"F1:        "
        f"{v2_strict['f1'] - v1_strict['f1']:+.1f} pp"
    )

    print(
        f"FPR:       "
        f"{v2_strict['fpr'] - v1_strict['fpr']:+.1f} pp"
    )

    print(
        f"FNR:       "
        f"{v2_strict['fnr'] - v1_strict['fnr']:+.1f} pp"
    )

    print()


    # ========================================================
    # Operational metrics
    # ========================================================

    print(
        "=" * 72
    )

    print(
        "SECONDARY METRICS — OPERATIONAL"
    )

    print(
        "(SUSPICIOUS + MALICIOUS = flagged)"
    )

    print(
        "=" * 72
    )

    print(
        f"V1 operational FPR: "
        f"{v1_operational['fpr']:.1f}%"
    )

    print(
        f"V2 operational FPR: "
        f"{v2_operational['fpr']:.1f}%"
    )

    print(
        f"Delta: "
        f"{v2_operational['fpr'] - v1_operational['fpr']:+.1f} pp"
    )

    print()


    # ========================================================
    # Transformations
    # ========================================================

    transform_rows = transform_analysis(
        v1,
        v2
    )


    print(
        "=" * 72
    )

    print(
        "STRICT FPR BY TRANSFORMATION"
    )

    print(
        "=" * 72
    )

    print(
        f"{'Transform':<18}"
        f"{'V1 FPR':>10}"
        f"{'V2 FPR':>10}"
        f"{'Delta':>10}"
        f"{'V1 FP':>8}"
        f"{'V2 FP':>8}"
    )

    print(
        "-" * 72
    )


    for row in transform_rows:

        print(
            f"{row['transformation']:<18}"
            f"{row['v1_strict_fpr']:>9.1f}%"
            f"{row['v2_strict_fpr']:>9.1f}%"
            f"{row['strict_fpr_delta_pp']:>+9.1f}"
            f"{row['v1_fp']:>8}"
            f"{row['v2_fp']:>8}"
        )


    print()


    # ========================================================
    # Pair changes
    # ========================================================

    paired = paired_analysis(
        v1,
        v2
    )


    print(
        "=" * 72
    )

    print(
        "PAIRED SAFE FALSE-POSITIVE CHANGES"
    )

    print(
        "=" * 72
    )

    safe_changes = paired[
        "safe_strict_fp_changes"
    ]


    print(
        f"Improved:  "
        f"{safe_changes['improved']}"
    )

    print(
        f"Worsened:  "
        f"{safe_changes['worsened']}"
    )

    print(
        f"Unchanged: "
        f"{safe_changes['unchanged']}"
    )

    print()


    print(
        "SAFE CHANGES BY TRANSFORMATION"
    )

    print(
        "-" * 72
    )


    for transformation, changes in (
        paired[
            "safe_by_transformation"
        ].items()
    ):

        print(
            f"{transformation:<18}"
            f"improved={changes['improved']:<3} "
            f"worsened={changes['worsened']:<3} "
            f"unchanged={changes['unchanged']:<3}"
        )


    # ========================================================
    # Category analysis
    # ========================================================

    category_rows = category_analysis(
        v1,
        v2
    )


    # ========================================================
    # Cost / runtime
    # ========================================================

    v1_credits = numeric_sum(
        v1,
        "used_credits"
    )

    v2_credits = numeric_sum(
        v2,
        "used_credits"
    )


    v1_runtime_mean = numeric_mean(
        v1,
        "runtime_seconds"
    )

    v2_runtime_mean = numeric_mean(
        v2,
        "runtime_seconds"
    )


    print()
    print(
        "=" * 72
    )

    print(
        "COST"
    )

    print(
        "=" * 72
    )

    print(
        f"V1 total credits: "
        f"{v1_credits:.6f}"
    )

    print(
        f"V2 total credits: "
        f"{v2_credits:.6f}"
    )

    print(
        f"Combined: "
        f"{v1_credits + v2_credits:.6f}"
    )


    if (
        v1_runtime_mean is not None
        and v2_runtime_mean is not None
    ):

        print(
            f"V1 mean model runtime: "
            f"{v1_runtime_mean:.3f}"
        )

        print(
            f"V2 mean model runtime: "
            f"{v2_runtime_mean:.3f}"
        )


    # ========================================================
    # Save outputs
    # ========================================================

    analysis = {
        "benchmark_version":
            "v2",

        "replicate":
            1,

        "benchmark_sha256":
            v1_hash,

        "paired_samples":
            len(v1_ids),

        "strict": {
            "v1":
                v1_strict,

            "v2":
                v2_strict,

            "delta_v2_minus_v1": {
                "accuracy_pp":
                    (
                        v2_strict["accuracy"]
                        - v1_strict["accuracy"]
                    ),

                "precision_pp":
                    (
                        v2_strict["precision"]
                        - v1_strict["precision"]
                    ),

                "recall_pp":
                    (
                        v2_strict["recall"]
                        - v1_strict["recall"]
                    ),

                "f1_pp":
                    (
                        v2_strict["f1"]
                        - v1_strict["f1"]
                    ),

                "fpr_pp":
                    (
                        v2_strict["fpr"]
                        - v1_strict["fpr"]
                    ),

                "fnr_pp":
                    (
                        v2_strict["fnr"]
                        - v1_strict["fnr"]
                    ),
            },
        },

        "operational": {
            "v1":
                v1_operational,

            "v2":
                v2_operational,
        },

        "by_transformation":
            transform_rows,

        "by_category":
            category_rows,

        "paired":
            paired,

        "cost": {
            "v1_total_credits":
                v1_credits,

            "v2_total_credits":
                v2_credits,

            "combined_total_credits":
                (
                    v1_credits
                    + v2_credits
                ),

            "v1_mean_runtime":
                v1_runtime_mean,

            "v2_mean_runtime":
                v2_runtime_mean,
        },
    }


    with OUTPUT_JSON.open(
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            analysis,
            file,
            ensure_ascii=False,
            indent=2
        )


    write_csv(
        OUTPUT_TRANSFORM_CSV,
        transform_rows
    )

    write_csv(
        OUTPUT_CATEGORY_CSV,
        category_rows
    )


    print()
    print(
        "=" * 72
    )

    print(
        "ANALYSIS COMPLETE"
    )

    print(
        "=" * 72
    )

    print(
        OUTPUT_JSON
    )

    print(
        OUTPUT_TRANSFORM_CSV
    )

    print(
        OUTPUT_CATEGORY_CSV
    )


if __name__ == "__main__":
    main()