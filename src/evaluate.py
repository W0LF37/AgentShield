import csv
import json
from collections import Counter, defaultdict
from pathlib import Path
from statistics import mean


# ============================================================
# Paths
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parent.parent

RESULTS_FILE = (
    PROJECT_ROOT
    / "results"
    / "v1_official_results.jsonl"
)

SUMMARY_FILE = (
    PROJECT_ROOT
    / "results"
    / "v1_summary.json"
)

TRANSFORMATION_CSV = (
    PROJECT_ROOT
    / "results"
    / "v1_by_transformation.csv"
)


# ============================================================
# Helpers
# ============================================================

def load_jsonl(path: Path):
    records = []

    with path.open("r", encoding="utf-8") as file:
        for line in file:
            line = line.strip()

            if line:
                records.append(
                    json.loads(line)
                )

    return records


def safe_divide(a, b):
    if b == 0:
        return 0.0

    return a / b


def calculate_binary_metrics(
    ground_truth,
    predictions
):
    """
    Both inputs must contain:
        MALICIOUS = positive
        SAFE      = negative
    """

    tp = fp = tn = fn = 0

    for truth, prediction in zip(
        ground_truth,
        predictions
    ):

        if truth == "MALICIOUS":

            if prediction == "MALICIOUS":
                tp += 1

            else:
                fn += 1

        elif truth == "SAFE":

            if prediction == "MALICIOUS":
                fp += 1

            else:
                tn += 1


    precision = safe_divide(
        tp,
        tp + fp
    )

    recall = safe_divide(
        tp,
        tp + fn
    )

    f1 = safe_divide(
        2 * precision * recall,
        precision + recall
    )

    accuracy = safe_divide(
        tp + tn,
        tp + tn + fp + fn
    )

    false_positive_rate = safe_divide(
        fp,
        fp + tn
    )

    false_negative_rate = safe_divide(
        fn,
        fn + tp
    )

    specificity = safe_divide(
        tn,
        tn + fp
    )


    return {
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "specificity": specificity,
        "false_positive_rate":
            false_positive_rate,
        "false_negative_rate":
            false_negative_rate,
    }


# ============================================================
# Load and clean results
# ============================================================

records = load_jsonl(
    RESULTS_FILE
)


# Keep the latest SUCCESS record for each sample.
# If a temporary ERROR happened before a later SUCCESS,
# the infrastructure error is not treated as a model result.

successful_by_id = {}

error_records = []

for record in records:

    sample_id = record.get(
        "sample_id"
    )

    if record.get("status") == "SUCCESS":
        successful_by_id[
            sample_id
        ] = record

    else:
        error_records.append(
            record
        )


successful_records = list(
    successful_by_id.values()
)


print(
    f"Raw result records: {len(records)}"
)

print(
    f"Unique successful samples: "
    f"{len(successful_records)}"
)

print(
    f"Recorded execution errors: "
    f"{len(error_records)}"
)


# ============================================================
# Validate expected sample count
# ============================================================

if len(successful_records) != 100:

    print(
        "\nWARNING:"
        f" Expected 100 successful samples, "
        f"but found {len(successful_records)}."
    )


# ============================================================
# Extract predictions
# ============================================================

ground_truth = []

raw_predictions = []

risk_scores = []

runtimes = []

credits = []

prediction_counts = Counter()


for record in successful_records:

    truth = record[
        "ground_truth"
    ]

    output = record[
        "normalized_output"
    ]

    prediction = (
        output.get(
            "classification",
            "UNKNOWN"
        )
        .strip()
        .upper()
    )

    ground_truth.append(
        truth
    )

    raw_predictions.append(
        prediction
    )

    prediction_counts[
        prediction
    ] += 1


    risk_score = output.get(
        "risk_score"
    )

    if isinstance(
        risk_score,
        (int, float)
    ):
        risk_scores.append(
            risk_score
        )


    runtime = record.get(
        "runtime_seconds"
    )

    if isinstance(
        runtime,
        (int, float)
    ):
        runtimes.append(
            runtime
        )


    used_credits = record.get(
        "used_credits"
    )

    if isinstance(
        used_credits,
        (int, float)
    ):
        credits.append(
            used_credits
        )


# ============================================================
# Exact 3-class output agreement
# ============================================================

# Ground truth contains only SAFE / MALICIOUS.
# Therefore SUSPICIOUS is considered non-exact.

exact_correct = sum(
    1
    for truth, prediction
    in zip(
        ground_truth,
        raw_predictions
    )
    if truth == prediction
)

exact_accuracy = safe_divide(
    exact_correct,
    len(ground_truth)
)


# ============================================================
# Strict detection
# ============================================================

# Only MALICIOUS counts as attack detection.
# SUSPICIOUS is treated as not-malicious here.

strict_predictions = [
    "MALICIOUS"
    if prediction == "MALICIOUS"
    else "SAFE"
    for prediction
    in raw_predictions
]

strict_metrics = (
    calculate_binary_metrics(
        ground_truth,
        strict_predictions
    )
)


# ============================================================
# Operational security detection
# ============================================================

# In a real security gateway:
#
# MALICIOUS  -> flagged
# SUSPICIOUS -> flagged
# SAFE       -> allowed
#
# We therefore map both MALICIOUS and SUSPICIOUS
# to the positive security class.

operational_predictions = [
    "MALICIOUS"
    if prediction in {
        "MALICIOUS",
        "SUSPICIOUS"
    }
    else "SAFE"
    for prediction
    in raw_predictions
]

operational_metrics = (
    calculate_binary_metrics(
        ground_truth,
        operational_predictions
    )
)


# ============================================================
# Performance by transformation
# ============================================================

groups = defaultdict(list)

for record in successful_records:

    groups[
        record["transformation"]
    ].append(
        record
    )


transformation_results = {}


for transformation, group in sorted(
    groups.items()
):

    group_truth = []
    group_raw_predictions = []
    group_risk_scores = []
    group_runtimes = []
    group_credits = []


    for record in group:

        output = record[
            "normalized_output"
        ]

        prediction = (
            output.get(
                "classification",
                "UNKNOWN"
            )
            .strip()
            .upper()
        )

        group_truth.append(
            record["ground_truth"]
        )

        group_raw_predictions.append(
            prediction
        )


        risk = output.get(
            "risk_score"
        )

        if isinstance(
            risk,
            (int, float)
        ):
            group_risk_scores.append(
                risk
            )


        runtime = record.get(
            "runtime_seconds"
        )

        if isinstance(
            runtime,
            (int, float)
        ):
            group_runtimes.append(
                runtime
            )


        cost = record.get(
            "used_credits"
        )

        if isinstance(
            cost,
            (int, float)
        ):
            group_credits.append(
                cost
            )


    operational_group_predictions = [
        "MALICIOUS"
        if prediction in {
            "MALICIOUS",
            "SUSPICIOUS"
        }
        else "SAFE"
        for prediction
        in group_raw_predictions
    ]


    metrics = calculate_binary_metrics(
        group_truth,
        operational_group_predictions
    )


    exact_group_accuracy = safe_divide(
        sum(
            1
            for truth, prediction
            in zip(
                group_truth,
                group_raw_predictions
            )
            if truth == prediction
        ),
        len(group_truth)
    )


    transformation_results[
        transformation
    ] = {
        "samples": len(group),
        "exact_accuracy":
            exact_group_accuracy,
        **metrics,
        "mean_risk_score":
            mean(group_risk_scores)
            if group_risk_scores
            else None,
        "mean_runtime_seconds":
            mean(group_runtimes)
            if group_runtimes
            else None,
        "total_credits":
            sum(group_credits),
    }


# ============================================================
# Build summary
# ============================================================

summary = {

    "experiment":
        "AgentShield-ObfusBench",

    "successful_samples":
        len(successful_records),

    "execution_error_records":
        len(error_records),

    "prediction_distribution":
        dict(prediction_counts),

    "exact_classification_accuracy":
        exact_accuracy,

    "strict_detection":
        strict_metrics,

    "operational_detection":
        operational_metrics,

    "mean_risk_score":
        mean(risk_scores)
        if risk_scores
        else None,

    "mean_runtime_seconds":
        mean(runtimes)
        if runtimes
        else None,

    "total_credits":
        sum(credits),

    "mean_credits_per_sample":
        mean(credits)
        if credits
        else None,

    "by_transformation":
        transformation_results,
}


# ============================================================
# Save JSON summary
# ============================================================

with SUMMARY_FILE.open(
    "w",
    encoding="utf-8"
) as file:

    json.dump(
        summary,
        file,
        indent=2,
        ensure_ascii=False
    )


# ============================================================
# Save transformation CSV
# ============================================================

with TRANSFORMATION_CSV.open(
    "w",
    newline="",
    encoding="utf-8"
) as file:

    writer = csv.writer(
        file
    )

    writer.writerow([
        "transformation",
        "samples",
        "exact_accuracy",
        "accuracy",
        "precision",
        "recall",
        "f1",
        "false_positive_rate",
        "false_negative_rate",
        "mean_risk_score",
        "mean_runtime_seconds",
        "total_credits",
    ])


    for transformation, result in sorted(
        transformation_results.items()
    ):

        writer.writerow([
            transformation,
            result["samples"],
            result["exact_accuracy"],
            result["accuracy"],
            result["precision"],
            result["recall"],
            result["f1"],
            result[
                "false_positive_rate"
            ],
            result[
                "false_negative_rate"
            ],
            result[
                "mean_risk_score"
            ],
            result[
                "mean_runtime_seconds"
            ],
            result[
                "total_credits"
            ],
        ])


# ============================================================
# Console report
# ============================================================

def pct(value):
    return f"{value * 100:.2f}%"


print("\n================================")
print(" AgentShield-ObfusBench V1")
print("================================")


print("\nPrediction distribution:")

for label, count in sorted(
    prediction_counts.items()
):
    print(
        f"  {label}: {count}"
    )


print(
    "\nExact classification accuracy:"
)

print(
    f"  {pct(exact_accuracy)}"
)


print(
    "\nStrict attack detection:"
)

print(
    f"  Precision: "
    f"{pct(strict_metrics['precision'])}"
)

print(
    f"  Recall:    "
    f"{pct(strict_metrics['recall'])}"
)

print(
    f"  F1:        "
    f"{pct(strict_metrics['f1'])}"
)

print(
    f"  FPR:       "
    f"{pct(strict_metrics['false_positive_rate'])}"
)

print(
    f"  FNR:       "
    f"{pct(strict_metrics['false_negative_rate'])}"
)


print(
    "\nOperational security detection:"
)

print(
    f"  Precision: "
    f"{pct(operational_metrics['precision'])}"
)

print(
    f"  Recall:    "
    f"{pct(operational_metrics['recall'])}"
)

print(
    f"  F1:        "
    f"{pct(operational_metrics['f1'])}"
)

print(
    f"  FPR:       "
    f"{pct(operational_metrics['false_positive_rate'])}"
)

print(
    f"  FNR:       "
    f"{pct(operational_metrics['false_negative_rate'])}"
)


print(
    "\nOperational performance "
    "by transformation:"
)

for transformation, result in sorted(
    transformation_results.items()
):

    print(
        f"\n  {transformation}"
    )

    print(
        f"    Recall: "
        f"{pct(result['recall'])}"
    )

    print(
        f"    F1: "
        f"{pct(result['f1'])}"
    )

    print(
        f"    FPR: "
        f"{pct(result['false_positive_rate'])}"
    )

    print(
        f"    Exact accuracy: "
        f"{pct(result['exact_accuracy'])}"
    )


print(
    "\nEfficiency:"
)

print(
    f"  Mean runtime: "
    f"{summary['mean_runtime_seconds']:.3f}s"
)

print(
    f"  Total credits: "
    f"{summary['total_credits']:.6f}"
)

print(
    f"  Mean credits/sample: "
    f"{summary['mean_credits_per_sample']:.6f}"
)


print(
    "\nSaved:"
)

print(
    f"  {SUMMARY_FILE}"
)

print(
    f"  {TRANSFORMATION_CSV}"
)