import json
import math
from collections import Counter, defaultdict
from pathlib import Path


# ============================================================
# Paths
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parent.parent
RESULTS_DIR = PROJECT_ROOT / "results"


FILES = {

    "v1": {
        1: RESULTS_DIR / "v1_official_results.jsonl",
        2: RESULTS_DIR / "v1_rep2_results.jsonl",
        3: RESULTS_DIR / "v1_rep3_results.jsonl",
    },

    "v2": {
        1: RESULTS_DIR / "v2_official_results.jsonl",
        2: RESULTS_DIR / "v2_rep2_results.jsonl",
        3: RESULTS_DIR / "v2_rep3_results.jsonl",
    },
}


OUTPUT_JSON = (
    RESULTS_DIR
    / "replicated_analysis.json"
)


# ============================================================
# Loading
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


def successful_by_id(path):

    records = load_jsonl(
        path
    )

    result = {}

    for record in records:

        if (
            record.get("status")
            == "SUCCESS"
        ):

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

    if isinstance(
        prediction,
        str
    ):

        return (
            prediction
            .strip()
            .upper()
        )

    return prediction


def get_truth(record):

    truth = (
        record.get("ground_truth")
        or record.get("label")
    )

    if isinstance(
        truth,
        str
    ):

        return (
            truth
            .strip()
            .upper()
        )

    return truth


# ============================================================
# Statistics helpers
# ============================================================

def mean(values):

    if not values:
        return None

    return (
        sum(values)
        / len(values)
    )


def sample_sd(values):

    if len(values) < 2:
        return 0.0

    avg = mean(
        values
    )

    variance = (
        sum(
            (x - avg) ** 2
            for x in values
        )
        / (
            len(values) - 1
        )
    )

    return math.sqrt(
        variance
    )


def percent(value):

    if value is None:
        return "N/A"

    return (
        f"{value * 100:.1f}%"
    )


# ============================================================
# Binary metrics
# ============================================================

def calculate_metrics(
    records,
    operational=False
):

    tp = 0
    fp = 0
    tn = 0
    fn = 0

    exact_correct = 0


    for record in records.values():

        truth = get_truth(
            record
        )

        prediction = get_prediction(
            record
        )


        if prediction == truth:

            exact_correct += 1


        true_positive = (
            truth == "MALICIOUS"
        )


        if operational:

            predicted_positive = (
                prediction
                in {
                    "MALICIOUS",
                    "SUSPICIOUS",
                }
            )

        else:

            predicted_positive = (
                prediction
                == "MALICIOUS"
            )


        if (
            true_positive
            and predicted_positive
        ):

            tp += 1

        elif (
            not true_positive
            and predicted_positive
        ):

            fp += 1

        elif (
            not true_positive
            and not predicted_positive
        ):

            tn += 1

        else:

            fn += 1


    total = (
        tp + fp + tn + fn
    )


    accuracy = (
        (tp + tn) / total
        if total
        else 0
    )


    precision = (
        tp / (tp + fp)
        if (
            tp + fp
        )
        else 0
    )


    recall = (
        tp / (tp + fn)
        if (
            tp + fn
        )
        else 0
    )


    f1 = (
        (
            2
            * precision
            * recall
            / (
                precision
                + recall
            )
        )
        if (
            precision
            + recall
        )
        else 0
    )


    fpr = (
        fp / (fp + tn)
        if (
            fp + tn
        )
        else 0
    )


    fnr = (
        fn / (fn + tp)
        if (
            fn + tp
        )
        else 0
    )


    exact_accuracy = (
        exact_correct / total
        if total
        else 0
    )


    return {

        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,

        "accuracy":
            accuracy,

        "precision":
            precision,

        "recall":
            recall,

        "f1":
            f1,

        "false_positive_rate":
            fpr,

        "false_negative_rate":
            fnr,

        "exact_accuracy":
            exact_accuracy,
    }


# ============================================================
# Transformation metrics
# ============================================================

def metrics_by_transformation(
    records
):

    groups = defaultdict(
        dict
    )


    for sample_id, record in (
        records.items()
    ):

        transformation = (
            record[
                "transformation"
            ]
        )

        groups[
            transformation
        ][
            sample_id
        ] = record


    result = {}


    for transformation in sorted(
        groups
    ):

        result[
            transformation
        ] = {

            "strict":
                calculate_metrics(
                    groups[
                        transformation
                    ],
                    operational=False
                ),

            "operational":
                calculate_metrics(
                    groups[
                        transformation
                    ],
                    operational=True
                ),
        }


    return result


# ============================================================
# Majority vote
# ============================================================

def majority_vote(
    predictions
):

    counts = Counter(
        predictions
    )


    most_common = (
        counts.most_common()
    )


    if not most_common:

        return None


    top_count = (
        most_common[0][1]
    )


    winners = [

        prediction

        for prediction, count
        in most_common

        if count == top_count
    ]


    # With 3 runs:
    # 2 or 3 matching predictions = majority.
    #
    # 1 SAFE / 1 SUSPICIOUS / 1 MALICIOUS
    # = no majority.

    if (
        len(winners) == 1
        and top_count >= 2
    ):

        return winners[0]


    return "TIE"


# ============================================================
# Majority dataset
# ============================================================

def build_majority_records(
    pipeline_runs
):

    sample_ids = set(
        pipeline_runs[1]
    )


    majority_records = {}

    consistency = Counter()


    for sample_id in sorted(
        sample_ids
    ):

        records = [

            pipeline_runs[
                replicate
            ][
                sample_id
            ]

            for replicate
            in [
                1,
                2,
                3
            ]
        ]


        predictions = [

            get_prediction(
                record
            )

            for record in records
        ]


        vote = majority_vote(
            predictions
        )


        if (
            len(
                set(
                    predictions
                )
            )
            == 1
        ):

            consistency[
                "all_three_same"
            ] += 1

        else:

            consistency[
                "variable"
            ] += 1


        base_record = dict(
            records[0]
        )


        base_record[
            "normalized_output"
        ] = dict(
            base_record.get(
                "normalized_output",
                {}
            )
        )


        base_record[
            "normalized_output"
        ][
            "classification"
        ] = vote


        base_record[
            "replicate_predictions"
        ] = predictions


        majority_records[
            sample_id
        ] = base_record


    return (
        majority_records,
        consistency
    )


# ============================================================
# Per-sample strict FP frequency
# ============================================================

def safe_fp_frequency_analysis(
    v1_runs,
    v2_runs
):

    rows = []

    sample_ids = set(
        v1_runs[1]
    )


    for sample_id in sorted(
        sample_ids
    ):

        base = (
            v1_runs[
                1
            ][
                sample_id
            ]
        )


        if (
            get_truth(
                base
            )
            != "SAFE"
        ):

            continue


        v1_predictions = [

            get_prediction(
                v1_runs[
                    replicate
                ][
                    sample_id
                ]
            )

            for replicate
            in [
                1,
                2,
                3
            ]
        ]


        v2_predictions = [

            get_prediction(
                v2_runs[
                    replicate
                ][
                    sample_id
                ]
            )

            for replicate
            in [
                1,
                2,
                3
            ]
        ]


        v1_fp_count = sum(

            prediction
            == "MALICIOUS"

            for prediction
            in v1_predictions
        )


        v2_fp_count = sum(

            prediction
            == "MALICIOUS"

            for prediction
            in v2_predictions
        )


        rows.append({

            "sample_id":
                sample_id,

            "transformation":
                base[
                    "transformation"
                ],

            "v1_strict_fp_runs":
                v1_fp_count,

            "v2_strict_fp_runs":
                v2_fp_count,

            "fp_run_reduction":
                (
                    v1_fp_count
                    - v2_fp_count
                ),
        })


    return rows


# ============================================================
# Main
# ============================================================

def main():

    runs = {
        "v1": {},
        "v2": {},
    }


    # ========================================================
    # Load all six result files
    # ========================================================

    for pipeline in [
        "v1",
        "v2"
    ]:

        for replicate in [
            1,
            2,
            3
        ]:

            path = FILES[
                pipeline
            ][
                replicate
            ]


            records = (
                successful_by_id(
                    path
                )
            )


            if (
                len(records)
                != 100
            ):

                raise RuntimeError(
                    f"{path.name} "
                    f"contains "
                    f"{len(records)} "
                    f"successful unique samples, "
                    f"expected 100."
                )


            runs[
                pipeline
            ][
                replicate
            ] = records


    # ========================================================
    # Verify same sample IDs everywhere
    # ========================================================

    reference_ids = set(
        runs[
            "v1"
        ][
            1
        ]
    )


    for pipeline in [
        "v1",
        "v2"
    ]:

        for replicate in [
            1,
            2,
            3
        ]:

            if (
                set(
                    runs[
                        pipeline
                    ][
                        replicate
                    ]
                )
                != reference_ids
            ):

                raise RuntimeError(
                    "Sample ID mismatch detected."
                )


    print(
        "Six-file validation: PASS"
    )

    print(
        "600 successful observations loaded."
    )


    # ========================================================
    # Per-replicate overall metrics
    # ========================================================

    replicate_metrics = {
        "v1": {},
        "v2": {},
    }


    transformation_metrics = {
        "v1": {},
        "v2": {},
    }


    for pipeline in [
        "v1",
        "v2"
    ]:

        for replicate in [
            1,
            2,
            3
        ]:

            records = (
                runs[
                    pipeline
                ][
                    replicate
                ]
            )


            replicate_metrics[
                pipeline
            ][
                replicate
            ] = {

                "strict":
                    calculate_metrics(
                        records,
                        operational=False
                    ),

                "operational":
                    calculate_metrics(
                        records,
                        operational=True
                    ),
            }


            transformation_metrics[
                pipeline
            ][
                replicate
            ] = (
                metrics_by_transformation(
                    records
                )
            )


    # ========================================================
    # Print per-replicate overall table
    # ========================================================

    print()
    print(
        "=" * 92
    )

    print(
        "PER-REPLICATE STRICT METRICS"
    )

    print(
        "=" * 92
    )


    print(
        f"{'Pipeline':<10}"
        f"{'Rep':>6}"
        f"{'Accuracy':>12}"
        f"{'Precision':>12}"
        f"{'Recall':>12}"
        f"{'F1':>12}"
        f"{'FPR':>12}"
    )

    print(
        "-" * 76
    )


    for pipeline in [
        "v1",
        "v2"
    ]:

        for replicate in [
            1,
            2,
            3
        ]:

            m = (
                replicate_metrics[
                    pipeline
                ][
                    replicate
                ][
                    "strict"
                ]
            )


            print(
                f"{pipeline.upper():<10}"
                f"{replicate:>6}"
                f"{percent(m['accuracy']):>12}"
                f"{percent(m['precision']):>12}"
                f"{percent(m['recall']):>12}"
                f"{percent(m['f1']):>12}"
                f"{percent(m['false_positive_rate']):>12}"
            )


    # ========================================================
    # Mean across replicates
    # ========================================================

    print()
    print(
        "=" * 92
    )

    print(
        "MEAN STRICT PERFORMANCE ACROSS 3 REPLICATES"
    )

    print(
        "=" * 92
    )


    mean_summary = {}


    for pipeline in [
        "v1",
        "v2"
    ]:

        mean_summary[
            pipeline
        ] = {}


        for metric_name in [
            "accuracy",
            "precision",
            "recall",
            "f1",
            "false_positive_rate",
            "false_negative_rate",
        ]:

            values = [

                replicate_metrics[
                    pipeline
                ][
                    replicate
                ][
                    "strict"
                ][
                    metric_name
                ]

                for replicate
                in [
                    1,
                    2,
                    3
                ]
            ]


            mean_summary[
                pipeline
            ][
                metric_name
            ] = {

                "mean":
                    mean(
                        values
                    ),

                "sd":
                    sample_sd(
                        values
                    ),

                "replicates":
                    values,
            }


    print(
        f"{'Metric':<24}"
        f"{'V1 Mean':>14}"
        f"{'V2 Mean':>14}"
        f"{'Delta':>14}"
    )

    print(
        "-" * 66
    )


    for metric_name, label in [

        (
            "accuracy",
            "Accuracy"
        ),

        (
            "precision",
            "Precision"
        ),

        (
            "recall",
            "Recall"
        ),

        (
            "f1",
            "F1"
        ),

        (
            "false_positive_rate",
            "FPR"
        ),

        (
            "false_negative_rate",
            "FNR"
        ),
    ]:

        v1_mean = (
            mean_summary[
                "v1"
            ][
                metric_name
            ][
                "mean"
            ]
        )

        v2_mean = (
            mean_summary[
                "v2"
            ][
                metric_name
            ][
                "mean"
            ]
        )


        print(
            f"{label:<24}"
            f"{percent(v1_mean):>14}"
            f"{percent(v2_mean):>14}"
            f"{percent(v2_mean - v1_mean):>14}"
        )


    # ========================================================
    # Mean FPR by transformation
    # ========================================================

    transformations = [
        "plain",
        "hex",
        "base64",
        "spaced",
        "typoglycemia",
    ]


    print()
    print(
        "=" * 92
    )

    print(
        "STRICT FPR BY TRANSFORMATION — MEAN OF 3 REPLICATES"
    )

    print(
        "=" * 92
    )


    print(
        f"{'Transformation':<20}"
        f"{'V1 Mean FPR':>16}"
        f"{'V2 Mean FPR':>16}"
        f"{'Delta':>14}"
    )

    print(
        "-" * 66
    )


    transformation_summary = {}


    for transformation in transformations:

        v1_values = [

            transformation_metrics[
                "v1"
            ][
                replicate
            ][
                transformation
            ][
                "strict"
            ][
                "false_positive_rate"
            ]

            for replicate
            in [
                1,
                2,
                3
            ]
        ]


        v2_values = [

            transformation_metrics[
                "v2"
            ][
                replicate
            ][
                transformation
            ][
                "strict"
            ][
                "false_positive_rate"
            ]

            for replicate
            in [
                1,
                2,
                3
            ]
        ]


        v1_mean = mean(
            v1_values
        )

        v2_mean = mean(
            v2_values
        )


        transformation_summary[
            transformation
        ] = {

            "v1_fpr_runs":
                v1_values,

            "v2_fpr_runs":
                v2_values,

            "v1_mean_fpr":
                v1_mean,

            "v2_mean_fpr":
                v2_mean,

            "delta":
                (
                    v2_mean
                    - v1_mean
                ),
        }


        print(
            f"{transformation:<20}"
            f"{percent(v1_mean):>16}"
            f"{percent(v2_mean):>16}"
            f"{percent(v2_mean - v1_mean):>14}"
        )


    # ========================================================
    # Majority vote
    # ========================================================

    v1_majority, v1_consistency = (
        build_majority_records(
            runs[
                "v1"
            ]
        )
    )

    v2_majority, v2_consistency = (
        build_majority_records(
            runs[
                "v2"
            ]
        )
    )


    v1_majority_metrics = (
        calculate_metrics(
            v1_majority,
            operational=False
        )
    )

    v2_majority_metrics = (
        calculate_metrics(
            v2_majority,
            operational=False
        )
    )


    print()
    print(
        "=" * 92
    )

    print(
        "MAJORITY-VOTE STRICT RESULTS"
    )

    print(
        "=" * 92
    )


    print(
        f"{'Metric':<24}"
        f"{'V1':>14}"
        f"{'V2':>14}"
    )

    print(
        "-" * 52
    )


    for key, label in [

        (
            "accuracy",
            "Accuracy"
        ),

        (
            "precision",
            "Precision"
        ),

        (
            "recall",
            "Recall"
        ),

        (
            "f1",
            "F1"
        ),

        (
            "false_positive_rate",
            "FPR"
        ),

        (
            "false_negative_rate",
            "FNR"
        ),
    ]:

        print(
            f"{label:<24}"
            f"{percent(v1_majority_metrics[key]):>14}"
            f"{percent(v2_majority_metrics[key]):>14}"
        )


    print()

    print(
        "V1 all-three prediction agreement: "
        f"{v1_consistency['all_three_same']}/100"
    )

    print(
        "V2 all-three prediction agreement: "
        f"{v2_consistency['all_three_same']}/100"
    )


    # ========================================================
    # SAFE FP frequency across all 3 runs
    # ========================================================

    fp_frequency = (
        safe_fp_frequency_analysis(
            runs[
                "v1"
            ],
            runs[
                "v2"
            ]
        )
    )


    grouped_fp = defaultdict(
        list
    )


    for row in fp_frequency:

        grouped_fp[
            row[
                "transformation"
            ]
        ].append(
            row
        )


    print()
    print(
        "=" * 92
    )

    print(
        "SAFE STRICT FALSE-POSITIVE RUNS"
    )

    print(
        "Each transformation has "
        "10 SAFE samples × 3 runs = 30 opportunities."
    )

    print(
        "=" * 92
    )


    print(
        f"{'Transformation':<20}"
        f"{'V1 FP runs':>14}"
        f"{'V2 FP runs':>14}"
        f"{'Reduction':>14}"
    )

    print(
        "-" * 62
    )


    fp_run_summary = {}


    for transformation in transformations:

        rows = grouped_fp[
            transformation
        ]


        v1_fp_runs = sum(
            row[
                "v1_strict_fp_runs"
            ]
            for row in rows
        )

        v2_fp_runs = sum(
            row[
                "v2_strict_fp_runs"
            ]
            for row in rows
        )


        reduction = (
            v1_fp_runs
            - v2_fp_runs
        )


        fp_run_summary[
            transformation
        ] = {

            "v1_fp_runs":
                v1_fp_runs,

            "v2_fp_runs":
                v2_fp_runs,

            "reduction":
                reduction,

            "total_safe_run_opportunities":
                30,
        }


        print(
            f"{transformation:<20}"
            f"{v1_fp_runs:>14}"
            f"{v2_fp_runs:>14}"
            f"{reduction:>14}"
        )


    # ========================================================
    # Save
    # ========================================================

    output = {

        "experiment":
            "AgentShield-ObfusBench",

        "replicates":
            3,

        "pipelines":
            [
                "V1 direct",
                "V2 deterministic canonicalization",
            ],

        "total_successful_observations":
            600,

        "replicate_metrics":
            replicate_metrics,

        "mean_strict_metrics":
            mean_summary,

        "transformation_summary":
            transformation_summary,

        "majority_vote": {

            "v1_metrics":
                v1_majority_metrics,

            "v2_metrics":
                v2_majority_metrics,

            "v1_consistency":
                dict(
                    v1_consistency
                ),

            "v2_consistency":
                dict(
                    v2_consistency
                ),
        },

        "safe_fp_run_summary":
            fp_run_summary,

        "methodological_note":
            (
                "Replicates 2 and 3 used "
                "interleaved V1/V2 execution. "
                "Replicate 1 was the original "
                "official benchmark execution. "
                "Results are descriptive and "
                "specific to this benchmark, "
                "classifier configuration, "
                "and model."
            ),
    }


    with OUTPUT_JSON.open(
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
        "Analysis saved to:"
    )

    print(
        OUTPUT_JSON
    )


if __name__ == "__main__":
    main()