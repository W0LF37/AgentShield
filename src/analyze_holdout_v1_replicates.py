import json
import statistics
from collections import Counter, defaultdict
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
RESULTS_DIR = PROJECT_ROOT / "results"

REPLICATES = [1, 2, 3]
EXPECTED_SAMPLES = 1000

OUTPUT_FILE = (
    RESULTS_DIR
    / "holdout_v1_replicated_analysis.json"
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


def pct(value):
    return value * 100.0


def mean(values):
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
        record
        for record in records
        if record.get("status") == "SUCCESS"
    ]

    if len(success) != EXPECTED_SAMPLES:
        raise RuntimeError(
            f"{pipeline} rep{replicate}: "
            f"expected {EXPECTED_SAMPLES} SUCCESS, "
            f"found {len(success)}."
        )

    sample_ids = [
        record["sample_id"]
        for record in success
    ]

    if len(set(sample_ids)) != EXPECTED_SAMPLES:
        raise RuntimeError(
            f"{pipeline} rep{replicate}: "
            f"duplicate sample IDs."
        )

    hashes = {
        record.get(
            "benchmark_sha256"
        )
        for record in success
    }

    if len(hashes) != 1:
        raise RuntimeError(
            f"{pipeline} rep{replicate}: "
            f"inconsistent benchmark hashes."
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

def majority_prediction(predictions):
    counts = Counter(
        predictions
    )

    return counts.most_common(
        1
    )[0][0]


def build_majority_records(
    replicate_records
):
    by_sample = defaultdict(list)

    metadata = {}


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

            metadata[
                sample_id
            ] = record


    majority_records = []

    same_three = 0


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
            same_three += 1


        record = dict(
            metadata[
                sample_id
            ]
        )

        record[
            "normalized_output"
        ] = {
            "classification":
                majority_prediction(
                    predictions
                )
        }

        majority_records.append(
            record
        )


    return (
        majority_records,
        same_three,
    )


# ============================================================
# Cost
# ============================================================

def cost_stats(records):

    credits = [
        float(
            record["used_credits"]
        )
        for record in records
        if isinstance(
            record.get("used_credits"),
            (int, float)
        )
    ]

    runtimes = [
        float(
            record["runtime_seconds"]
        )
        for record in records
        if isinstance(
            record.get("runtime_seconds"),
            (int, float)
        )
    ]


    return {
        "total_credits":
            sum(credits),

        "mean_credits":
            (
                mean(credits)
                if credits
                else 0.0
            ),

        "mean_runtime":
            (
                mean(runtimes)
                if runtimes
                else 0.0
            ),
    }


# ============================================================
# Main
# ============================================================

def main():

    print("=" * 78)

    print(
        "AgentShield-ObfusBench"
    )

    print(
        "Synthetic Holdout v1 — "
        "Three-Replicate Analysis"
    )

    print("=" * 78)

    print()


    all_data = {
        "v1": {},
        "v2": {},
    }

    all_hashes = set()


    # ========================================================
    # Load six files
    # ========================================================

    for replicate in REPLICATES:

        for pipeline in [
            "v1",
            "v2",
        ]:

            path = (
                RESULTS_DIR
                / (
                    f"holdout_v1_"
                    f"{pipeline}_rep"
                    f"{replicate}_results.jsonl"
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


            all_hashes.update({
                record[
                    "benchmark_sha256"
                ]
                for record
                in records
            })


            print(
                f"{pipeline.upper()} "
                f"Rep{replicate}: "
                f"{len(records)} SUCCESS"
            )


    if len(all_hashes) != 1:
        raise RuntimeError(
            "Different holdout benchmark "
            "hashes were used."
        )


    benchmark_hash = next(
        iter(all_hashes)
    )


    print()
    print(
        "Holdout SHA256:"
    )

    print(
        benchmark_hash
    )


    # ========================================================
    # Per replicate
    # ========================================================

    replicate_metrics = {
        "v1": {},
        "v2": {},
    }


    print()
    print("=" * 78)

    print(
        "STRICT METRICS BY REPLICATE"
    )

    print("=" * 78)


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

    print("-" * 78)


    for pipeline in [
        "v1",
        "v2",
    ]:

        for replicate in REPLICATES:

            strict = calculate_metrics(
                all_data[
                    pipeline
                ][
                    replicate
                ],
                "strict"
            )

            operational = calculate_metrics(
                all_data[
                    pipeline
                ][
                    replicate
                ],
                "operational"
            )


            replicate_metrics[
                pipeline
            ][
                replicate
            ] = {
                "strict":
                    strict,

                "operational":
                    operational,
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

    summary = {
        "v1": {},
        "v2": {},
    }


    print()
    print("=" * 78)

    print(
        "MEAN ± SD ACROSS 3 REPLICATES"
    )

    print("=" * 78)


    for pipeline in [
        "v1",
        "v2",
    ]:

        print(
            pipeline.upper()
        )

        print("-" * 78)


        for metric in [
            "accuracy",
            "precision",
            "recall",
            "f1",
            "fpr",
            "fnr",
        ]:

            values = [
                replicate_metrics[
                    pipeline
                ][
                    replicate
                ][
                    "strict"
                ][
                    metric
                ]
                for replicate
                in REPLICATES
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

    print("-" * 78)


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
    # Transformations
    # ========================================================

    transformations = sorted({
        record[
            "transformation"
        ]
        for record
        in all_data["v1"][1]
    })


    transform_summary = {}


    print()
    print("=" * 78)

    print(
        "STRICT FPR BY TRANSFORMATION "
        "— MEAN ACROSS 3 RUNS"
    )

    print("=" * 78)


    print(
        f"{'Transform':<18}"
        f"{'V1 mean':>12}"
        f"{'V2 mean':>12}"
        f"{'Delta':>12}"
        f"{'V1 FP':>10}"
        f"{'V2 FP':>10}"
    )

    print("-" * 78)


    for transformation in transformations:

        v1_fprs = []
        v2_fprs = []

        v1_fp_total = 0
        v2_fp_total = 0


        for replicate in REPLICATES:

            v1_subset = [
                record
                for record
                in all_data[
                    "v1"
                ][
                    replicate
                ]
                if (
                    record[
                        "transformation"
                    ]
                    == transformation
                )
            ]

            v2_subset = [
                record
                for record
                in all_data[
                    "v2"
                ][
                    replicate
                ]
                if (
                    record[
                        "transformation"
                    ]
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
                v1_metrics["fpr"]
            )

            v2_fprs.append(
                v2_metrics["fpr"]
            )

            v1_fp_total += (
                v1_metrics["fp"]
            )

            v2_fp_total += (
                v2_metrics["fp"]
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
    # Operational FPR
    # ========================================================

    print()
    print("=" * 78)

    print(
        "OPERATIONAL FPR "
        "— MEAN ACROSS 3 RUNS"
    )

    print("=" * 78)


    for pipeline in [
        "v1",
        "v2",
    ]:

        values = [
            replicate_metrics[
                pipeline
            ][
                replicate
            ][
                "operational"
            ][
                "fpr"
            ]
            for replicate
            in REPLICATES
        ]


        print(
            f"{pipeline.upper()}: "
            f"{mean(values):.2f}% "
            f"± {sd(values):.2f}"
        )


    # ========================================================
    # Majority vote
    # ========================================================

    majority_results = {}


    print()
    print("=" * 78)

    print(
        "MAJORITY-VOTE RESULTS"
    )

    print("=" * 78)


    for pipeline in [
        "v1",
        "v2",
    ]:

        (
            majority_records,
            same_three
        ) = build_majority_records(
            [
                all_data[
                    pipeline
                ][replicate]
                for replicate
                in REPLICATES
            ]
        )


        strict = calculate_metrics(
            majority_records,
            "strict"
        )


        operational = calculate_metrics(
            majority_records,
            "operational"
        )


        majority_results[
            pipeline
        ] = {
            "strict":
                strict,

            "operational":
                operational,

            "all_three_same":
                same_three,

            "variable_samples":
                (
                    EXPECTED_SAMPLES
                    - same_three
                ),
        }


        print(
            pipeline.upper()
        )

        print("-" * 78)

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
            f"FNR: "
            f"{strict['fnr']:.1f}%"
        )

        print(
            f"TP={strict['tp']} "
            f"FP={strict['fp']} "
            f"TN={strict['tn']} "
            f"FN={strict['fn']}"
        )

        print(
            f"All 3 runs same: "
            f"{same_three}/"
            f"{EXPECTED_SAMPLES}"
        )

        print(
            f"Variable samples: "
            f"{EXPECTED_SAMPLES - same_three}"
        )

        print()


    # ========================================================
    # Cost / runtime
    # ========================================================

    cost_summary = {}


    print("=" * 78)

    print(
        "TOTAL COST / RUNTIME"
    )

    print("=" * 78)


    for pipeline in [
        "v1",
        "v2",
    ]:

        combined_records = []

        for replicate in REPLICATES:
            combined_records.extend(
                all_data[
                    pipeline
                ][
                    replicate
                ]
            )


        stats = cost_stats(
            combined_records
        )


        cost_summary[
            pipeline
        ] = stats


        print(
            f"{pipeline.upper()} "
            f"classifications: "
            f"{len(combined_records)}"
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
    # Save
    # ========================================================

    output = {
        "dataset":
            "synthetic_holdout_v1",

        "benchmark_sha256":
            benchmark_hash,

        "replicates":
            REPLICATES,

        "total_classifications":
            6000,

        "per_replicate":
            replicate_metrics,

        "mean_sd":
            summary,

        "by_transformation":
            transform_summary,

        "majority_vote":
            majority_results,

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
    print("=" * 78)

    print(
        "ANALYSIS COMPLETE"
    )

    print("=" * 78)

    print(
        OUTPUT_FILE
    )


if __name__ == "__main__":
    main()