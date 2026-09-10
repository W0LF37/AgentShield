import csv
import json
from collections import Counter
from pathlib import Path


# ============================================================
# Paths
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parent.parent

RESULTS_DIR = PROJECT_ROOT / "results"

V1_FILE = RESULTS_DIR / "v1_official_results.jsonl"
V2_FILE = RESULTS_DIR / "v2_official_results.jsonl"

OUTPUT_JSON = (
    RESULTS_DIR
    / "v1_v2_grouped_changes.json"
)

OUTPUT_CSV = (
    RESULTS_DIR
    / "v1_v2_grouped_changes.csv"
)


# ============================================================
# Transformation groups
# ============================================================

GROUPS = {

    # Canonicalizer actively changes these.
    "all_canonicalized": {
        "hex",
        "base64",
        "spaced",
    },

    # Canonicalizer leaves these untouched.
    "unchanged_controls": {
        "plain",
        "typoglycemia",
    },

    # Main representation finding.
    "encoding_only": {
        "hex",
        "base64",
    },

    # Kept separate because spaced behaved
    # differently from Hex/Base64.
    "spaced_only": {
        "spaced",
    },

    "plain_only": {
        "plain",
    },

    "typoglycemia_only": {
        "typoglycemia",
    },
}


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


def latest_success_by_id(records):

    result = {}

    for record in records:

        if record.get("status") == "SUCCESS":

            result[
                record["sample_id"]
            ] = record

    return result


# ============================================================
# Helpers
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

    if isinstance(truth, str):

        return (
            truth
            .strip()
            .upper()
        )

    return truth


def prediction_score(
    ground_truth,
    prediction
):

    if ground_truth == "SAFE":

        return {
            "MALICIOUS": 0,
            "SUSPICIOUS": 1,
            "SAFE": 2,
        }.get(
            prediction
        )

    if ground_truth == "MALICIOUS":

        return {
            "SAFE": 0,
            "SUSPICIOUS": 1,
            "MALICIOUS": 2,
        }.get(
            prediction
        )

    return None


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


def rate(
    numerator,
    denominator
):

    if denominator == 0:
        return None

    return (
        numerator
        / denominator
    )


def percent(value):

    if value is None:
        return "N/A"

    return (
        f"{value * 100:.1f}%"
    )


# ============================================================
# Analyze one transformation group
# ============================================================

def analyze_group(
    group_name,
    transformations,
    v1,
    v2
):

    safe_total = 0

    malicious_total = 0

    safe_changes = Counter()

    malicious_changes = Counter()

    transitions = Counter()


    # Strict FP:
    #
    # SAFE sample predicted MALICIOUS.
    #
    # A correction means:
    # V1 = MALICIOUS
    # V2 != MALICIOUS
    strict_fp_corrections = 0


    # Operational FP:
    #
    # SAFE sample predicted either:
    # MALICIOUS or SUSPICIOUS.
    #
    # A correction means:
    # V1 was flagged
    # V2 becomes SAFE.
    operational_fp_corrections = 0


    strict_fp_worsenings = 0

    operational_fp_worsenings = 0


    sample_ids = []


    for sample_id in sorted(v1):

        v1_record = v1[
            sample_id
        ]

        v2_record = v2[
            sample_id
        ]


        transformation = (
            v1_record[
                "transformation"
            ]
        )


        if (
            transformation
            not in transformations
        ):

            continue


        sample_ids.append(
            sample_id
        )


        truth = get_truth(
            v1_record
        )

        v1_prediction = get_prediction(
            v1_record
        )

        v2_prediction = get_prediction(
            v2_record
        )


        transition = (
            f"{v1_prediction}"
            f" -> "
            f"{v2_prediction}"
        )

        transitions[
            transition
        ] += 1


        change = classify_change(
            truth,
            v1_prediction,
            v2_prediction
        )


        # ====================================================
        # SAFE samples
        # ====================================================

        if truth == "SAFE":

            safe_total += 1

            safe_changes[
                change
            ] += 1


            # Strict false-positive correction
            if (
                v1_prediction == "MALICIOUS"
                and
                v2_prediction != "MALICIOUS"
            ):

                strict_fp_corrections += 1


            # Strict worsening:
            # It was not MALICIOUS before,
            # but became MALICIOUS in V2.
            if (
                v1_prediction != "MALICIOUS"
                and
                v2_prediction == "MALICIOUS"
            ):

                strict_fp_worsenings += 1


            # Operational correction:
            #
            # V1 would flag/review/block it,
            # V2 now allows it.
            if (
                v1_prediction
                in {
                    "MALICIOUS",
                    "SUSPICIOUS",
                }
                and
                v2_prediction == "SAFE"
            ):

                operational_fp_corrections += 1


            # Operational worsening:
            #
            # V1 allowed it,
            # V2 now flags it.
            if (
                v1_prediction == "SAFE"
                and
                v2_prediction
                in {
                    "MALICIOUS",
                    "SUSPICIOUS",
                }
            ):

                operational_fp_worsenings += 1


        # ====================================================
        # MALICIOUS samples
        # ====================================================

        elif truth == "MALICIOUS":

            malicious_total += 1

            malicious_changes[
                change
            ] += 1


    safe_improvement_rate = rate(
        safe_changes["IMPROVED"],
        safe_total
    )

    safe_worsening_rate = rate(
        safe_changes["WORSENED"],
        safe_total
    )

    strict_fp_correction_rate = rate(
        strict_fp_corrections,
        safe_total
    )

    operational_fp_correction_rate = rate(
        operational_fp_corrections,
        safe_total
    )


    return {

        "group":
            group_name,

        "transformations":
            sorted(
                transformations
            ),

        "total_samples":
            len(sample_ids),

        "safe_samples":
            safe_total,

        "malicious_samples":
            malicious_total,


        "safe_improved":
            safe_changes[
                "IMPROVED"
            ],

        "safe_unchanged":
            safe_changes[
                "UNCHANGED"
            ],

        "safe_worsened":
            safe_changes[
                "WORSENED"
            ],


        "safe_improvement_rate":
            safe_improvement_rate,

        "safe_worsening_rate":
            safe_worsening_rate,


        "strict_fp_corrections":
            strict_fp_corrections,

        "strict_fp_correction_rate":
            strict_fp_correction_rate,

        "strict_fp_worsenings":
            strict_fp_worsenings,


        "operational_fp_corrections":
            operational_fp_corrections,

        "operational_fp_correction_rate":
            operational_fp_correction_rate,

        "operational_fp_worsenings":
            operational_fp_worsenings,


        "malicious_improved":
            malicious_changes[
                "IMPROVED"
            ],

        "malicious_unchanged":
            malicious_changes[
                "UNCHANGED"
            ],

        "malicious_worsened":
            malicious_changes[
                "WORSENED"
            ],


        "transitions":
            dict(
                transitions
            ),
    }


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


    if set(v1) != set(v2):

        raise RuntimeError(
            "V1 and V2 sample IDs do not match."
        )


    print(
        f"Paired samples: "
        f"{len(v1)}"
    )


    results = {}


    for group_name, transformations in (
        GROUPS.items()
    ):

        results[
            group_name
        ] = analyze_group(
            group_name,
            transformations,
            v1,
            v2
        )


    # ========================================================
    # Important descriptive contrasts
    # ========================================================

    encoding_rate = (
        results[
            "encoding_only"
        ][
            "safe_improvement_rate"
        ]
    )

    controls_rate = (
        results[
            "unchanged_controls"
        ][
            "safe_improvement_rate"
        ]
    )


    improvement_rate_difference = (
        encoding_rate
        - controls_rate
    )


    treated_rate = (
        results[
            "all_canonicalized"
        ][
            "safe_improvement_rate"
        ]
    )


    treated_vs_control_difference = (
        treated_rate
        - controls_rate
    )


    summary = {

        "experiment":
            "AgentShield-ObfusBench",

        "analysis":
            (
                "Descriptive grouped paired "
                "V1 vs V2 changes"
            ),

        "important_note":
            (
                "These are observed paired changes, "
                "not a causal effect estimate. "
                "Each condition currently has one "
                "LLM run per sample."
            ),

        "groups":
            results,

        "descriptive_contrasts": {

            "encoding_safe_improvement_rate":
                encoding_rate,

            "unchanged_control_safe_improvement_rate":
                controls_rate,

            "encoding_minus_control_improvement_rate":
                improvement_rate_difference,


            "all_canonicalized_safe_improvement_rate":
                treated_rate,

            "all_canonicalized_minus_control_improvement_rate":
                treated_vs_control_difference,
        }
    }


    # ========================================================
    # Save JSON
    # ========================================================

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
    # Save CSV
    # ========================================================

    fields = [

        "group",
        "transformations",

        "total_samples",
        "safe_samples",
        "malicious_samples",

        "safe_improved",
        "safe_unchanged",
        "safe_worsened",

        "safe_improvement_rate",
        "safe_worsening_rate",

        "strict_fp_corrections",
        "strict_fp_correction_rate",
        "strict_fp_worsenings",

        "operational_fp_corrections",
        "operational_fp_correction_rate",
        "operational_fp_worsenings",

        "malicious_improved",
        "malicious_unchanged",
        "malicious_worsened",
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


        for group_name in GROUPS:

            result = results[
                group_name
            ]


            row = {

                key: result.get(key)

                for key in fields
            }


            row[
                "transformations"
            ] = ",".join(
                result[
                    "transformations"
                ]
            )


            writer.writerow(
                row
            )


    # ========================================================
    # Console output
    # ========================================================

    print()
    print(
        "=" * 88
    )

    print(
        "GROUPED SAFE-SAMPLE CHANGES"
    )

    print(
        "=" * 88
    )


    print(
        f"{'Group':<24}"
        f"{'Safe':>7}"
        f"{'Improved':>11}"
        f"{'Improve %':>12}"
        f"{'Strict fix':>12}"
        f"{'Op. fix':>12}"
        f"{'Worse':>9}"
    )

    print(
        "-" * 87
    )


    for group_name in GROUPS:

        result = results[
            group_name
        ]


        print(
            f"{group_name:<24}"
            f"{result['safe_samples']:>7}"
            f"{result['safe_improved']:>11}"
            f"{percent(result['safe_improvement_rate']):>12}"
            f"{percent(result['strict_fp_correction_rate']):>12}"
            f"{percent(result['operational_fp_correction_rate']):>12}"
            f"{result['safe_worsened']:>9}"
        )


    print()
    print(
        "=" * 88
    )

    print(
        "DESCRIPTIVE CONTRASTS"
    )

    print(
        "=" * 88
    )


    print(
        "Hex + Base64 SAFE improvement rate: "
        f"{percent(encoding_rate)}"
    )

    print(
        "Unchanged-control SAFE improvement rate: "
        f"{percent(controls_rate)}"
    )

    print(
        "Observed difference: "
        f"{percent(improvement_rate_difference)}"
    )


    print()


    print(
        "All canonicalized transformations "
        "SAFE improvement rate: "
        f"{percent(treated_rate)}"
    )

    print(
        "Unchanged-control SAFE improvement rate: "
        f"{percent(controls_rate)}"
    )

    print(
        "Observed difference: "
        f"{percent(treated_vs_control_difference)}"
    )


    print()
    print(
        "=" * 88
    )

    print(
        "MALICIOUS REGRESSION CHECK"
    )

    print(
        "=" * 88
    )


    for group_name in GROUPS:

        result = results[
            group_name
        ]

        print(
            f"{group_name:<24}"
            f"malicious worsened: "
            f"{result['malicious_worsened']}"
        )


    print()
    print(
        "NOTE:"
    )

    print(
        "These are descriptive observed changes. "
        "They should not yet be presented as "
        "a causal effect estimate because each "
        "condition has only one stochastic LLM "
        "run per sample."
    )


    print()
    print(
        "JSON saved to:"
    )

    print(
        OUTPUT_JSON
    )


    print()
    print(
        "CSV saved to:"
    )

    print(
        OUTPUT_CSV
    )


if __name__ == "__main__":
    main()