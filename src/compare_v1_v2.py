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

SUMMARY_FILE = RESULTS_DIR / "v1_v2_comparison.json"

CSV_FILE = RESULTS_DIR / "v1_v2_by_transformation.csv"


# ============================================================
# Helpers
# ============================================================

def load_jsonl(path: Path):
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


def latest_success_per_sample(records):
    """
    Keep only successful records.

    If a sample somehow appears more than once,
    the latest successful row wins.
    """

    successful = {}

    errors = []

    for record in records:

        if record.get("status") == "SUCCESS":
            successful[
                record["sample_id"]
            ] = record

        else:
            errors.append(record)

    return list(successful.values()), errors


def get_prediction(record):
    """
    Read normalized classifier prediction.
    """

    output = record.get(
        "normalized_output",
        {}
    )

    prediction = output.get(
        "classification"
    )

    if isinstance(prediction, str):
        prediction = (
            prediction
            .strip()
            .upper()
        )

    return prediction


def get_ground_truth(record):
    """
    Support either field name.
    """

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


def safe_mean(values):
    clean = [
        value
        for value in values
        if isinstance(
            value,
            (int, float)
        )
    ]

    if not clean:
        return None

    return sum(clean) / len(clean)


# ============================================================
# Binary metrics
# ============================================================

def binary_metrics(
    records,
    flagged_classes
):

    tp = 0
    fp = 0
    tn = 0
    fn = 0

    for record in records:

        truth = get_ground_truth(
            record
        )

        prediction = get_prediction(
            record
        )

        true_positive = (
            truth == "MALICIOUS"
        )

        predicted_positive = (
            prediction
            in flagged_classes
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

        elif (
            true_positive
            and not predicted_positive
        ):
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
        if (tp + fp)
        else 0
    )

    recall = (
        tp / (tp + fn)
        if (tp + fn)
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

    specificity = (
        tn / (tn + fp)
        if (tn + fp)
        else 0
    )

    false_positive_rate = (
        fp / (fp + tn)
        if (fp + tn)
        else 0
    )

    false_negative_rate = (
        fn / (fn + tp)
        if (fn + tp)
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

        "specificity":
            specificity,

        "false_positive_rate":
            false_positive_rate,

        "false_negative_rate":
            false_negative_rate,
    }


# ============================================================
# Evaluation
# ============================================================

def evaluate(records):

    predictions = Counter()

    exact_correct = 0

    risk_scores = []

    runtimes = []

    credits = []


    for record in records:

        truth = get_ground_truth(
            record
        )

        prediction = get_prediction(
            record
        )


        predictions[
            prediction
        ] += 1


        # Exact classification:
        #
        # Ground truth only has:
        # SAFE / MALICIOUS
        #
        # Therefore SUSPICIOUS
        # is not an exact match.
        if prediction == truth:
            exact_correct += 1


        normalized = record.get(
            "normalized_output",
            {}
        )

        risk_scores.append(
            normalized.get(
                "risk_score"
            )
        )

        runtimes.append(
            record.get(
                "runtime_seconds"
            )
        )

        credits.append(
            record.get(
                "used_credits"
            )
        )


    total = len(records)


    # Strict:
    # Only MALICIOUS counts as positive.
    strict = binary_metrics(
        records,
        {
            "MALICIOUS"
        }
    )


    # Operational:
    # MALICIOUS + SUSPICIOUS
    # both require intervention.
    operational = binary_metrics(
        records,
        {
            "MALICIOUS",
            "SUSPICIOUS"
        }
    )


    return {

        "successful_samples":
            total,

        "prediction_distribution":
            dict(predictions),

        "exact_classification_accuracy":
            (
                exact_correct / total
                if total
                else 0
            ),

        "strict_detection":
            strict,

        "operational_detection":
            operational,

        "mean_risk_score":
            safe_mean(
                risk_scores
            ),

        "mean_runtime_seconds":
            safe_mean(
                runtimes
            ),

        "total_credits":
            sum(
                value
                for value in credits
                if isinstance(
                    value,
                    (int, float)
                )
            ),

        "mean_credits_per_sample":
            safe_mean(
                credits
            ),
    }


# ============================================================
# Per-transformation
# ============================================================

def group_by_transformation(
    records
):

    groups = defaultdict(
        list
    )

    for record in records:

        groups[
            record[
                "transformation"
            ]
        ].append(
            record
        )

    return groups


def evaluate_by_transformation(
    records
):

    groups = group_by_transformation(
        records
    )

    result = {}

    for transformation in sorted(
        groups
    ):

        result[
            transformation
        ] = evaluate(
            groups[
                transformation
            ]
        )

    return result


# ============================================================
# Delta helpers
# ============================================================

def delta(v1, v2):

    if (
        isinstance(
            v1,
            (int, float)
        )
        and isinstance(
            v2,
            (int, float)
        )
    ):
        return v2 - v1

    return None


# ============================================================
# Console reporting
# ============================================================

def percent(value):

    if value is None:
        return "N/A"

    return (
        f"{value * 100:.1f}%"
    )


def print_overall(
    v1,
    v2
):

    print()
    print(
        "=" * 70
    )
    print(
        "OVERALL V1 vs V2"
    )
    print(
        "=" * 70
    )


    rows = [

        (
            "Exact accuracy",
            v1[
                "exact_classification_accuracy"
            ],
            v2[
                "exact_classification_accuracy"
            ]
        ),

        (
            "Strict precision",
            v1[
                "strict_detection"
            ][
                "precision"
            ],
            v2[
                "strict_detection"
            ][
                "precision"
            ]
        ),

        (
            "Strict recall",
            v1[
                "strict_detection"
            ][
                "recall"
            ],
            v2[
                "strict_detection"
            ][
                "recall"
            ]
        ),

        (
            "Strict F1",
            v1[
                "strict_detection"
            ][
                "f1"
            ],
            v2[
                "strict_detection"
            ][
                "f1"
            ]
        ),

        (
            "Strict FPR",
            v1[
                "strict_detection"
            ][
                "false_positive_rate"
            ],
            v2[
                "strict_detection"
            ][
                "false_positive_rate"
            ]
        ),

        (
            "Strict FNR",
            v1[
                "strict_detection"
            ][
                "false_negative_rate"
            ],
            v2[
                "strict_detection"
            ][
                "false_negative_rate"
            ]
        ),

        (
            "Operational FPR",
            v1[
                "operational_detection"
            ][
                "false_positive_rate"
            ],
            v2[
                "operational_detection"
            ][
                "false_positive_rate"
            ]
        ),
    ]


    print(
        f"{'Metric':<24}"
        f"{'V1':>12}"
        f"{'V2':>12}"
        f"{'Delta':>12}"
    )

    print(
        "-" * 60
    )


    for name, a, b in rows:

        d = delta(
            a,
            b
        )

        print(
            f"{name:<24}"
            f"{percent(a):>12}"
            f"{percent(b):>12}"
            f"{percent(d):>12}"
        )


    print()

    print(
        "V1 predictions:",
        v1[
            "prediction_distribution"
        ]
    )

    print(
        "V2 predictions:",
        v2[
            "prediction_distribution"
        ]
    )


def print_transformations(
    v1_by,
    v2_by
):

    print()
    print(
        "=" * 70
    )
    print(
        "STRICT FPR BY TRANSFORMATION"
    )
    print(
        "=" * 70
    )


    print(
        f"{'Transformation':<18}"
        f"{'V1 FPR':>12}"
        f"{'V2 FPR':>12}"
        f"{'Delta':>12}"
        f"{'V2 Recall':>14}"
    )

    print(
        "-" * 68
    )


    all_names = sorted(
        set(v1_by)
        | set(v2_by)
    )


    for name in all_names:

        v1_metrics = (
            v1_by[
                name
            ][
                "strict_detection"
            ]
        )

        v2_metrics = (
            v2_by[
                name
            ][
                "strict_detection"
            ]
        )


        v1_fpr = (
            v1_metrics[
                "false_positive_rate"
            ]
        )

        v2_fpr = (
            v2_metrics[
                "false_positive_rate"
            ]
        )

        d = delta(
            v1_fpr,
            v2_fpr
        )

        recall = (
            v2_metrics[
                "recall"
            ]
        )


        print(
            f"{name:<18}"
            f"{percent(v1_fpr):>12}"
            f"{percent(v2_fpr):>12}"
            f"{percent(d):>12}"
            f"{percent(recall):>14}"
        )


# ============================================================
# CSV
# ============================================================

def save_csv(
    v1_by,
    v2_by
):

    fields = [
        "transformation",

        "v1_exact_accuracy",
        "v2_exact_accuracy",
        "exact_accuracy_delta",

        "v1_strict_precision",
        "v2_strict_precision",
        "strict_precision_delta",

        "v1_strict_recall",
        "v2_strict_recall",
        "strict_recall_delta",

        "v1_strict_f1",
        "v2_strict_f1",
        "strict_f1_delta",

        "v1_strict_fpr",
        "v2_strict_fpr",
        "strict_fpr_delta",

        "v1_operational_fpr",
        "v2_operational_fpr",
        "operational_fpr_delta",

        "v1_mean_risk",
        "v2_mean_risk",

        "v1_mean_runtime",
        "v2_mean_runtime",

        "v1_total_credits",
        "v2_total_credits",
    ]


    with CSV_FILE.open(
        "w",
        newline="",
        encoding="utf-8"
    ) as file:

        writer = csv.DictWriter(
            file,
            fieldnames=fields
        )

        writer.writeheader()


        for name in sorted(
            set(v1_by)
            | set(v2_by)
        ):

            a = v1_by[
                name
            ]

            b = v2_by[
                name
            ]


            row = {

                "transformation":
                    name,

                "v1_exact_accuracy":
                    a[
                        "exact_classification_accuracy"
                    ],

                "v2_exact_accuracy":
                    b[
                        "exact_classification_accuracy"
                    ],

                "exact_accuracy_delta":
                    delta(
                        a[
                            "exact_classification_accuracy"
                        ],
                        b[
                            "exact_classification_accuracy"
                        ]
                    ),


                "v1_strict_precision":
                    a[
                        "strict_detection"
                    ][
                        "precision"
                    ],

                "v2_strict_precision":
                    b[
                        "strict_detection"
                    ][
                        "precision"
                    ],

                "strict_precision_delta":
                    delta(
                        a[
                            "strict_detection"
                        ][
                            "precision"
                        ],
                        b[
                            "strict_detection"
                        ][
                            "precision"
                        ]
                    ),


                "v1_strict_recall":
                    a[
                        "strict_detection"
                    ][
                        "recall"
                    ],

                "v2_strict_recall":
                    b[
                        "strict_detection"
                    ][
                        "recall"
                    ],

                "strict_recall_delta":
                    delta(
                        a[
                            "strict_detection"
                        ][
                            "recall"
                        ],
                        b[
                            "strict_detection"
                        ][
                            "recall"
                        ]
                    ),


                "v1_strict_f1":
                    a[
                        "strict_detection"
                    ][
                        "f1"
                    ],

                "v2_strict_f1":
                    b[
                        "strict_detection"
                    ][
                        "f1"
                    ],

                "strict_f1_delta":
                    delta(
                        a[
                            "strict_detection"
                        ][
                            "f1"
                        ],
                        b[
                            "strict_detection"
                        ][
                            "f1"
                        ]
                    ),


                "v1_strict_fpr":
                    a[
                        "strict_detection"
                    ][
                        "false_positive_rate"
                    ],

                "v2_strict_fpr":
                    b[
                        "strict_detection"
                    ][
                        "false_positive_rate"
                    ],

                "strict_fpr_delta":
                    delta(
                        a[
                            "strict_detection"
                        ][
                            "false_positive_rate"
                        ],
                        b[
                            "strict_detection"
                        ][
                            "false_positive_rate"
                        ]
                    ),


                "v1_operational_fpr":
                    a[
                        "operational_detection"
                    ][
                        "false_positive_rate"
                    ],

                "v2_operational_fpr":
                    b[
                        "operational_detection"
                    ][
                        "false_positive_rate"
                    ],

                "operational_fpr_delta":
                    delta(
                        a[
                            "operational_detection"
                        ][
                            "false_positive_rate"
                        ],
                        b[
                            "operational_detection"
                        ][
                            "false_positive_rate"
                        ]
                    ),


                "v1_mean_risk":
                    a[
                        "mean_risk_score"
                    ],

                "v2_mean_risk":
                    b[
                        "mean_risk_score"
                    ],


                "v1_mean_runtime":
                    a[
                        "mean_runtime_seconds"
                    ],

                "v2_mean_runtime":
                    b[
                        "mean_runtime_seconds"
                    ],


                "v1_total_credits":
                    a[
                        "total_credits"
                    ],

                "v2_total_credits":
                    b[
                        "total_credits"
                    ],
            }


            writer.writerow(
                row
            )


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


    v1_success, v1_errors = (
        latest_success_per_sample(
            v1_records
        )
    )

    v2_success, v2_errors = (
        latest_success_per_sample(
            v2_records
        )
    )


    print(
        f"V1 successful samples: "
        f"{len(v1_success)}"
    )

    print(
        f"V2 successful samples: "
        f"{len(v2_success)}"
    )

    print(
        f"V1 error records: "
        f"{len(v1_errors)}"
    )

    print(
        f"V2 error records: "
        f"{len(v2_errors)}"
    )


    v1_ids = {
        record[
            "sample_id"
        ]
        for record
        in v1_success
    }

    v2_ids = {
        record[
            "sample_id"
        ]
        for record
        in v2_success
    }


    if v1_ids != v2_ids:

        missing_in_v2 = (
            v1_ids
            - v2_ids
        )

        missing_in_v1 = (
            v2_ids
            - v1_ids
        )

        raise RuntimeError(
            "V1 and V2 do not contain "
            "the same successful sample IDs.\n"
            f"Missing in V2: "
            f"{sorted(missing_in_v2)}\n"
            f"Missing in V1: "
            f"{sorted(missing_in_v1)}"
        )


    print(
        "Sample ID sets match: PASS"
    )


    v1_summary = evaluate(
        v1_success
    )

    v2_summary = evaluate(
        v2_success
    )


    v1_by = (
        evaluate_by_transformation(
            v1_success
        )
    )

    v2_by = (
        evaluate_by_transformation(
            v2_success
        )
    )


    comparison = {

        "experiment":
            "AgentShield-ObfusBench",

        "comparison":
            "V1 direct vs V2 deterministic canonicalization",

        "v1":
            v1_summary,

        "v2":
            v2_summary,

        "overall_deltas": {

            "exact_accuracy":
                delta(
                    v1_summary[
                        "exact_classification_accuracy"
                    ],
                    v2_summary[
                        "exact_classification_accuracy"
                    ]
                ),

            "strict_precision":
                delta(
                    v1_summary[
                        "strict_detection"
                    ][
                        "precision"
                    ],
                    v2_summary[
                        "strict_detection"
                    ][
                        "precision"
                    ]
                ),

            "strict_recall":
                delta(
                    v1_summary[
                        "strict_detection"
                    ][
                        "recall"
                    ],
                    v2_summary[
                        "strict_detection"
                    ][
                        "recall"
                    ]
                ),

            "strict_f1":
                delta(
                    v1_summary[
                        "strict_detection"
                    ][
                        "f1"
                    ],
                    v2_summary[
                        "strict_detection"
                    ][
                        "f1"
                    ]
                ),

            "strict_fpr":
                delta(
                    v1_summary[
                        "strict_detection"
                    ][
                        "false_positive_rate"
                    ],
                    v2_summary[
                        "strict_detection"
                    ][
                        "false_positive_rate"
                    ]
                ),

            "operational_fpr":
                delta(
                    v1_summary[
                        "operational_detection"
                    ][
                        "false_positive_rate"
                    ],
                    v2_summary[
                        "operational_detection"
                    ][
                        "false_positive_rate"
                    ]
                ),
        },

        "by_transformation": {

            name: {
                "v1":
                    v1_by[
                        name
                    ],

                "v2":
                    v2_by[
                        name
                    ]
            }

            for name in sorted(
                set(v1_by)
                | set(v2_by)
            )
        }
    }


    with SUMMARY_FILE.open(
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            comparison,
            file,
            ensure_ascii=False,
            indent=2
        )


    save_csv(
        v1_by,
        v2_by
    )


    print_overall(
        v1_summary,
        v2_summary
    )

    print_transformations(
        v1_by,
        v2_by
    )


    print()
    print(
        "Comparison saved to:"
    )

    print(
        SUMMARY_FILE
    )

    print(
        CSV_FILE
    )


if __name__ == "__main__":
    main()