import json
import statistics
from collections import Counter, defaultdict
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
RESULTS_DIR = PROJECT_ROOT / "results"

REPLICATES = [1, 2, 3]

EXPECTED_SAMPLES = 500

ALLOWED_PREDICTIONS = {
    "SAFE",
    "SUSPICIOUS",
    "MALICIOUS",
}

OUTPUT_FILE = (
    RESULTS_DIR
    / "benchmark_v2_replicated_analysis.json"
)


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
                    f"Invalid JSON in {path.name}, "
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


def pct(value):

    return value * 100.0


def mean(values):

    if not values:
        return 0.0

    return statistics.mean(values)


def sd(values):

    if len(values) < 2:
        return 0.0

    return statistics.stdev(values)


# ============================================================
# Validation
# ============================================================

def validate_records(
    records,
    pipeline,
    replicate
):

    success = [
        r
        for r in records
        if r.get("status") == "SUCCESS"
    ]

    if len(success) != EXPECTED_SAMPLES:

        raise RuntimeError(
            f"{pipeline} rep{replicate}: "
            f"expected {EXPECTED_SAMPLES} SUCCESS, "
            f"found {len(success)}."
        )

    sample_ids = [
        r.get("sample_id")
        for r in success
    ]

    if len(set(sample_ids)) != EXPECTED_SAMPLES:

        raise RuntimeError(
            f"{pipeline} rep{replicate}: "
            "duplicate sample IDs."
        )

    invalid = {
        prediction(r)
        for r in success
        if prediction(r)
        not in ALLOWED_PREDICTIONS
    }

    if invalid:

        raise RuntimeError(
            f"{pipeline} rep{replicate}: "
            f"invalid predictions {invalid}"
        )

    hashes = {
        r.get("benchmark_sha256")
        for r in success
    }

    if len(hashes) != 1:

        raise RuntimeError(
            f"{pipeline} rep{replicate}: "
            "inconsistent benchmark hashes."
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
                f"Unknown mode: {mode}"
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

        else:
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
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,

        "accuracy":
            pct(accuracy),

        "precision":
            pct(precision),

        "recall":
            pct(recall),

        "f1":
            pct(f1),

        "fpr":
            pct(fpr),

        "fnr":
            pct(fnr),

        "exact_accuracy":
            pct(exact_accuracy),

        "prediction_counts":
            dict(prediction_counts),
    }


# ============================================================
# Majority vote
# ============================================================

def majority_prediction(
    predictions
):

    counts = Counter(
        predictions
    )

    return counts.most_common(
        1
    )[0][0]


def build_majority_records(
    replicate_records
):

    by_sample = defaultdict(
        list
    )

    sample_metadata = {}


    for records in replicate_records:

        for record in records:

            sample_id = record[
                "sample_id"
            ]

            by_sample[
                sample_id
            ].append(
                prediction(record)
            )

            sample_metadata[
                sample_id
            ] = record


    majority_records = []

    consistency_count = 0


    for sample_id, predictions in (
        by_sample.items()
    ):

        if len(predictions) != 3:

            raise RuntimeError(
                f"{sample_id}: expected "
                f"3 predictions, "
                f"found {len(predictions)}."
            )


        if len(
            set(predictions)
        ) == 1:

            consistency_count += 1


        base = dict(
            sample_metadata[
                sample_id
            ]
        )

        base[
            "normalized_output"
        ] = {
            "classification":
                majority_prediction(
                    predictions
                )
        }

        majority_records.append(
            base
        )


    return (
        majority_records,
        consistency_count,
    )


# ============================================================
# Per-transformation
# ============================================================

def transformation_metrics(
    records
):

    transformations = sorted({
        r[
            "transformation"
        ]
        for r in records
    })

    result = {}


    for transformation in transformations:

        subset = [
            r
            for r in records
            if (
                r["transformation"]
                == transformation
            )
        ]

        result[
            transformation
        ] = {
            "strict":
                calculate_metrics(
                    subset,
                    "strict"
                ),

            "operational":
                calculate_metrics(
                    subset,
                    "operational"
                ),
        }


    return result


# ============================================================
# Cost / runtime
# ============================================================

def cost_stats(
    records
):

    credits = [
        float(
            r["used_credits"]
        )
        for r in records
        if isinstance(
            r.get("used_credits"),
            (int, float)
        )
    ]

    runtimes = [
        float(
            r["runtime_seconds"]
        )
        for r in records
        if isinstance(
            r.get("runtime_seconds"),
            (int, float)
        )
    ]


    return {
        "total_credits":
            sum(credits),

        "mean_credits":
            mean(credits),

        "mean_runtime":
            mean(runtimes),
    }


# ============================================================
# Main
# ============================================================

def main():

    print(
        "=" * 78
    )

    print(
        "AgentShield-ObfusBench"
    )

    print(
        "Benchmark v2 — "
        "Three-Replicate Analysis"
    )

    print(
        "=" * 78
    )

    print()


    all_data = {
        "v1": {},
        "v2": {},
    }

    all_hashes = set()


    # ========================================================
    # Load all six result files
    # ========================================================

    for replicate in REPLICATES:

        for pipeline in [
            "v1",
            "v2",
        ]:

            path = (
                RESULTS_DIR
                / (
                    "benchmark_v2_"
                    f"{pipeline}_rep"
                    f"{replicate}_"
                    "results.jsonl"
                )
            )


            if not path.exists():

                raise FileNotFoundError(
                    f"Missing file:\n{path}"
                )


            raw = load_jsonl(
                path
            )


            records = validate_records(
                raw,
                pipeline.upper(),
                replicate
            )


            all_data[
                pipeline
            ][
                replicate
            ] = records


            file_hashes = {
                r[
                    "benchmark_sha256"
                ]
                for r in records
            }

            all_hashes.update(
                file_hashes
            )


            print(
                f"{pipeline.upper()} "
                f"Rep{replicate}: "
                f"{len(records)} SUCCESS"
            )


    if len(all_hashes) != 1:

        raise RuntimeError(
            "Different benchmark hashes "
            "were used across runs."
        )


    benchmark_hash = next(
        iter(all_hashes)
    )


    print()
    print(
        "Benchmark SHA256:"
    )

    print(
        benchmark_hash
    )

    print()


    # ========================================================
    # Per replicate metrics
    # ========================================================

    replicate_results = {
        "v1": {},
        "v2": {},
    }


    print(
        "=" * 78
    )

    print(
        "STRICT METRICS BY REPLICATE"
    )

    print(
        "=" * 78
    )

    print(
        f"{'Pipeline':<10}"
        f"{'Rep':>5}"
        f"{'Acc':>9}"
        f"{'Prec':>9}"
        f"{'Recall':>9}"
        f"{'F1':>9}"
        f"{'FPR':>9}"
        f"{'FNR':>9}"
    )

    print(
        "-" * 78
    )


    for pipeline in [
        "v1",
        "v2",
    ]:

        for replicate in REPLICATES:

            records = all_data[
                pipeline
            ][
                replicate
            ]


            strict = calculate_metrics(
                records,
                "strict"
            )

            operational = calculate_metrics(
                records,
                "operational"
            )


            replicate_results[
                pipeline
            ][
                replicate
            ] = {
                "strict":
                    strict,

                "operational":
                    operational,

                "cost":
                    cost_stats(
                        records
                    ),
            }


            print(
                f"{pipeline.upper():<10}"
                f"{replicate:>5}"
                f"{strict['accuracy']:>8.1f}%"
                f"{strict['precision']:>8.1f}%"
                f"{strict['recall']:>8.1f}%"
                f"{strict['f1']:>8.1f}%"
                f"{strict['fpr']:>8.1f}%"
                f"{strict['fnr']:>8.1f}%"
            )


    # ========================================================
    # Mean ± SD
    # ========================================================

    summary = {}


    print()
    print(
        "=" * 78
    )

    print(
        "MEAN ± SD ACROSS 3 REPLICATES"
    )

    print(
        "=" * 78
    )


    for pipeline in [
        "v1",
        "v2",
    ]:

        summary[
            pipeline
        ] = {}


        print(
            pipeline.upper()
        )

        print(
            "-" * 78
        )


        for metric in [
            "accuracy",
            "precision",
            "recall",
            "f1",
            "fpr",
            "fnr",
        ]:

            values = [
                replicate_results[
                    pipeline
                ][
                    rep
                ][
                    "strict"
                ][
                    metric
                ]
                for rep in REPLICATES
            ]


            summary[
                pipeline
            ][
                metric
            ] = {
                "mean":
                    mean(values),

                "sd":
                    sd(values),

                "values":
                    values,
            }


            print(
                f"{metric:<12}"
                f"{mean(values):>7.2f}%"
                f" ± "
                f"{sd(values):.2f}"
            )


        print()


    print(
        "MEAN DELTA — V2 minus V1"
    )

    print(
        "-" * 78
    )


    for metric in [
        "accuracy",
        "precision",
        "recall",
        "f1",
        "fpr",
        "fnr",
    ]:

        delta = (
            summary[
                "v2"
            ][
                metric
            ][
                "mean"
            ]
            -
            summary[
                "v1"
            ][
                metric
            ][
                "mean"
            ]
        )


        print(
            f"{metric:<12}"
            f"{delta:+.2f} pp"
        )


    # ========================================================
    # Per-transform mean FPR
    # ========================================================

    transform_summary = {}


    transformations = sorted({
        r[
            "transformation"
        ]
        for r in all_data[
            "v1"
        ][1]
    })


    print()
    print(
        "=" * 78
    )

    print(
        "STRICT FPR BY TRANSFORMATION "
        "— MEAN ACROSS 3 RUNS"
    )

    print(
        "=" * 78
    )

    print(
        f"{'Transform':<18}"
        f"{'V1 mean':>12}"
        f"{'V2 mean':>12}"
        f"{'Delta':>12}"
        f"{'V1 FP':>10}"
        f"{'V2 FP':>10}"
    )

    print(
        "-" * 78
    )


    for transformation in transformations:

        v1_fprs = []
        v2_fprs = []

        v1_fp_total = 0
        v2_fp_total = 0


        for replicate in REPLICATES:

            v1_subset = [
                r
                for r in all_data[
                    "v1"
                ][replicate]
                if (
                    r["transformation"]
                    == transformation
                )
            ]

            v2_subset = [
                r
                for r in all_data[
                    "v2"
                ][replicate]
                if (
                    r["transformation"]
                    == transformation
                )
            ]


            v1_metrics = calculate_metrics(
                v1_subset,
                "strict"
            )

            v2_metrics = calculate_metrics(
                v2_subset,
                "strict"
            )


            v1_fprs.append(
                v1_metrics[
                    "fpr"
                ]
            )

            v2_fprs.append(
                v2_metrics[
                    "fpr"
                ]
            )

            v1_fp_total += (
                v1_metrics[
                    "fp"
                ]
            )

            v2_fp_total += (
                v2_metrics[
                    "fp"
                ]
            )


        v1_mean = mean(
            v1_fprs
        )

        v2_mean = mean(
            v2_fprs
        )

        delta = (
            v2_mean
            - v1_mean
        )


        transform_summary[
            transformation
        ] = {
            "v1_fpr_values":
                v1_fprs,

            "v2_fpr_values":
                v2_fprs,

            "v1_fpr_mean":
                v1_mean,

            "v2_fpr_mean":
                v2_mean,

            "delta_pp":
                delta,

            "v1_fp_total":
                v1_fp_total,

            "v2_fp_total":
                v2_fp_total,

            "safe_opportunities":
                150,
        }


        print(
            f"{transformation:<18}"
            f"{v1_mean:>11.1f}%"
            f"{v2_mean:>11.1f}%"
            f"{delta:>+11.1f}"
            f"{v1_fp_total:>10}"
            f"{v2_fp_total:>10}"
        )


    # ========================================================
    # Majority vote
    # ========================================================

    majority = {}


    print()
    print(
        "=" * 78
    )

    print(
        "MAJORITY-VOTE RESULTS"
    )

    print(
        "=" * 78
    )


    for pipeline in [
        "v1",
        "v2",
    ]:

        records_list = [
            all_data[
                pipeline
            ][rep]
            for rep in REPLICATES
        ]


        (
            majority_records,
            consistency_count,
        ) = build_majority_records(
            records_list
        )


        strict = calculate_metrics(
            majority_records,
            "strict"
        )

        operational = calculate_metrics(
            majority_records,
            "operational"
        )


        majority[
            pipeline
        ] = {
            "strict":
                strict,

            "operational":
                operational,

            "all_three_same":
                consistency_count,

            "variable_samples":
                (
                    EXPECTED_SAMPLES
                    - consistency_count
                ),
        }


        print(
            pipeline.upper()
        )

        print(
            "-" * 78
        )

        print(
            f"Accuracy: "
            f"{strict['accuracy']:.1f}%"
        )

        print(
            f"Precision: "
            f"{strict['precision']:.1f}%"
        )

        print(
            f"Recall: "
            f"{strict['recall']:.1f}%"
        )

        print(
            f"F1: "
            f"{strict['f1']:.1f}%"
        )

        print(
            f"FPR: "
            f"{strict['fpr']:.1f}%"
        )

        print(
            f"TP={strict['tp']} "
            f"FP={strict['fp']} "
            f"TN={strict['tn']} "
            f"FN={strict['fn']}"
        )

        print(
            f"All 3 runs same: "
            f"{consistency_count}/"
            f"{EXPECTED_SAMPLES}"
        )

        print(
            f"Variable samples: "
            f"{EXPECTED_SAMPLES - consistency_count}"
        )

        print()


    # ========================================================
    # Total cost
    # ========================================================

    cost_summary = {}


    print(
        "=" * 78
    )

    print(
        "TOTAL COST / RUNTIME"
    )

    print(
        "=" * 78
    )


    for pipeline in [
        "v1",
        "v2",
    ]:

        all_records = []

        for replicate in REPLICATES:

            all_records.extend(
                all_data[
                    pipeline
                ][replicate]
            )


        stats = cost_stats(
            all_records
        )

        cost_summary[
            pipeline
        ] = stats


        print(
            f"{pipeline.upper()} "
            f"total classifications: "
            f"{len(all_records)}"
        )

        print(
            f"{pipeline.upper()} "
            f"total credits: "
            f"{stats['total_credits']:.6f}"
        )

        print(
            f"{pipeline.upper()} "
            f"mean credits/call: "
            f"{stats['mean_credits']:.6f}"
        )

        print(
            f"{pipeline.upper()} "
            f"mean model runtime: "
            f"{stats['mean_runtime']:.3f}"
        )

        print()


    combined_credits = (
        cost_summary[
            "v1"
        ][
            "total_credits"
        ]
        +
        cost_summary[
            "v2"
        ][
            "total_credits"
        ]
    )


    print(
        f"Combined classifications: "
        f"{EXPECTED_SAMPLES * 2 * 3}"
    )

    print(
        f"Combined credits: "
        f"{combined_credits:.6f}"
    )


    # ========================================================
    # Save JSON
    # ========================================================

    output = {
        "benchmark_version":
            "v2",

        "benchmark_sha256":
            benchmark_hash,

        "replicates":
            REPLICATES,

        "total_classifications":
            EXPECTED_SAMPLES
            * 2
            * 3,

        "per_replicate":
            replicate_results,

        "mean_sd":
            summary,

        "by_transformation":
            transform_summary,

        "majority_vote":
            majority,

        "cost":
            {
                "v1":
                    cost_summary[
                        "v1"
                    ],

                "v2":
                    cost_summary[
                        "v2"
                    ],

                "combined_credits":
                    combined_credits,
            },
    }


    with OUTPUT_FILE.open(
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
    print(
        "=" * 78
    )

    print(
        "ANALYSIS COMPLETE"
    )

    print(
        "=" * 78
    )

    print(
        OUTPUT_FILE
    )


if __name__ == "__main__":
    main()