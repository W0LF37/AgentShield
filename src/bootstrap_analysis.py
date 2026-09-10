import json
import random
from pathlib import Path
from collections import defaultdict


# ============================================================
# Configuration
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

OUTPUT_FILE = RESULTS_DIR / "cluster_bootstrap_analysis.json"

BOOTSTRAP_ITERATIONS = 20000
RANDOM_SEED = 42


GROUPS = {
    "overall": {
        "plain",
        "hex",
        "base64",
        "spaced",
        "typoglycemia",
    },

    "encoding_only": {
        "hex",
        "base64",
    },

    "all_canonicalized": {
        "hex",
        "base64",
        "spaced",
    },

    "unchanged_controls": {
        "plain",
        "typoglycemia",
    },
}


# ============================================================
# Loading helpers
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

    result = {}

    for record in load_jsonl(path):

        if record.get("status") == "SUCCESS":

            result[
                record["sample_id"]
            ] = record

    return result


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

        return prediction.strip().upper()

    return prediction


def get_truth(record):

    truth = (
        record.get("ground_truth")
        or record.get("label")
    )

    if isinstance(truth, str):

        return truth.strip().upper()

    return truth


# ============================================================
# Percentile helper
# ============================================================

def percentile(
    values,
    percentile_value
):

    if not values:
        return None

    values = sorted(values)

    index = (
        percentile_value
        / 100
        * (
            len(values) - 1
        )
    )

    lower = int(index)

    upper = min(
        lower + 1,
        len(values) - 1
    )

    weight = (
        index - lower
    )

    return (
        values[lower]
        * (1 - weight)
        +
        values[upper]
        * weight
    )


def percent(value):

    return (
        f"{value * 100:.1f}%"
    )


# ============================================================
# Build clustered SAFE observations
# ============================================================

def build_safe_clusters(runs):

    clusters = defaultdict(
        lambda: {
            "v1": [],
            "v2": [],
        }
    )


    reference = runs[
        "v1"
    ][
        1
    ]


    for sample_id, base_record in (
        reference.items()
    ):

        if (
            get_truth(
                base_record
            )
            != "SAFE"
        ):

            continue


        base_id = (
            base_record[
                "base_id"
            ]
        )

        transformation = (
            base_record[
                "transformation"
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

                record = (
                    runs[
                        pipeline
                    ][
                        replicate
                    ][
                        sample_id
                    ]
                )


                clusters[
                    base_id
                ][
                    pipeline
                ].append({

                    "transformation":
                        transformation,

                    "prediction":
                        get_prediction(
                            record
                        ),
                })


    return clusters


# ============================================================
# FPR calculation
# ============================================================

def strict_fpr_for_cluster_sample(
    sampled_base_ids,
    clusters,
    pipeline,
    transformations
):

    fp = 0
    total = 0


    for base_id in sampled_base_ids:

        observations = (
            clusters[
                base_id
            ][
                pipeline
            ]
        )


        for observation in observations:

            if (
                observation[
                    "transformation"
                ]
                not in transformations
            ):

                continue


            total += 1


            if (
                observation[
                    "prediction"
                ]
                == "MALICIOUS"
            ):

                fp += 1


    if total == 0:
        return 0.0


    return (
        fp / total
    )


# ============================================================
# Analyze one group
# ============================================================

def analyze_group(
    group_name,
    transformations,
    clusters
):

    base_ids = sorted(
        clusters.keys()
    )


    # --------------------------------------------------------
    # Observed result
    # --------------------------------------------------------

    observed_v1_fpr = (
        strict_fpr_for_cluster_sample(
            base_ids,
            clusters,
            "v1",
            transformations
        )
    )


    observed_v2_fpr = (
        strict_fpr_for_cluster_sample(
            base_ids,
            clusters,
            "v2",
            transformations
        )
    )


    observed_reduction = (
        observed_v1_fpr
        - observed_v2_fpr
    )


    # --------------------------------------------------------
    # Cluster bootstrap
    # --------------------------------------------------------

    bootstrap_reductions = []


    for _ in range(
        BOOTSTRAP_ITERATIONS
    ):

        sampled_base_ids = [

            random.choice(
                base_ids
            )

            for _ in range(
                len(base_ids)
            )
        ]


        v1_fpr = (
            strict_fpr_for_cluster_sample(
                sampled_base_ids,
                clusters,
                "v1",
                transformations
            )
        )


        v2_fpr = (
            strict_fpr_for_cluster_sample(
                sampled_base_ids,
                clusters,
                "v2",
                transformations
            )
        )


        reduction = (
            v1_fpr
            - v2_fpr
        )


        bootstrap_reductions.append(
            reduction
        )


    lower = percentile(
        bootstrap_reductions,
        2.5
    )

    upper = percentile(
        bootstrap_reductions,
        97.5
    )


    probability_positive = (

        sum(
            value > 0
            for value
            in bootstrap_reductions
        )

        / len(
            bootstrap_reductions
        )
    )


    return {

        "group":
            group_name,

        "transformations":
            sorted(
                transformations
            ),

        "safe_base_clusters":
            len(base_ids),

        "observed_v1_fpr":
            observed_v1_fpr,

        "observed_v2_fpr":
            observed_v2_fpr,

        "observed_fpr_reduction":
            observed_reduction,

        "bootstrap_95_ci": [
            lower,
            upper,
        ],

        "bootstrap_probability_reduction_positive":
            probability_positive,
    }


# ============================================================
# Bootstrap difference in reductions
# ============================================================

def bootstrap_reduction_contrast(
    clusters,
    group_a,
    group_b
):

    base_ids = sorted(
        clusters.keys()
    )


    observed_a = (

        strict_fpr_for_cluster_sample(
            base_ids,
            clusters,
            "v1",
            group_a
        )

        -

        strict_fpr_for_cluster_sample(
            base_ids,
            clusters,
            "v2",
            group_a
        )
    )


    observed_b = (

        strict_fpr_for_cluster_sample(
            base_ids,
            clusters,
            "v1",
            group_b
        )

        -

        strict_fpr_for_cluster_sample(
            base_ids,
            clusters,
            "v2",
            group_b
        )
    )


    observed_contrast = (
        observed_a
        - observed_b
    )


    bootstrap_values = []


    for _ in range(
        BOOTSTRAP_ITERATIONS
    ):

        sampled_base_ids = [

            random.choice(
                base_ids
            )

            for _ in range(
                len(base_ids)
            )
        ]


        a_reduction = (

            strict_fpr_for_cluster_sample(
                sampled_base_ids,
                clusters,
                "v1",
                group_a
            )

            -

            strict_fpr_for_cluster_sample(
                sampled_base_ids,
                clusters,
                "v2",
                group_a
            )
        )


        b_reduction = (

            strict_fpr_for_cluster_sample(
                sampled_base_ids,
                clusters,
                "v1",
                group_b
            )

            -

            strict_fpr_for_cluster_sample(
                sampled_base_ids,
                clusters,
                "v2",
                group_b
            )
        )


        bootstrap_values.append(
            a_reduction
            - b_reduction
        )


    lower = percentile(
        bootstrap_values,
        2.5
    )

    upper = percentile(
        bootstrap_values,
        97.5
    )


    probability_positive = (

        sum(
            value > 0
            for value
            in bootstrap_values
        )

        / len(
            bootstrap_values
        )
    )


    return {

        "observed_contrast":
            observed_contrast,

        "bootstrap_95_ci": [
            lower,
            upper,
        ],

        "bootstrap_probability_positive":
            probability_positive,
    }


# ============================================================
# Main
# ============================================================

def main():

    random.seed(
        RANDOM_SEED
    )


    runs = {
        "v1": {},
        "v2": {},
    }


    # --------------------------------------------------------
    # Load six files
    # --------------------------------------------------------

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
                    f"has "
                    f"{len(records)} "
                    f"successful samples; "
                    f"expected 100."
                )


            runs[
                pipeline
            ][
                replicate
            ] = records


    # --------------------------------------------------------
    # Validate matching IDs
    # --------------------------------------------------------

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

            current_ids = set(
                runs[
                    pipeline
                ][
                    replicate
                ]
            )


            if (
                current_ids
                != reference_ids
            ):

                raise RuntimeError(
                    "Sample ID mismatch."
                )


    print(
        "Six-file validation: PASS"
    )


    # --------------------------------------------------------
    # Build SAFE clusters
    # --------------------------------------------------------

    clusters = (
        build_safe_clusters(
            runs
        )
    )


    print(
        f"SAFE base clusters: "
        f"{len(clusters)}"
    )


    # --------------------------------------------------------
    # Analyze groups
    # --------------------------------------------------------

    results = {}


    for group_name, transformations in (
        GROUPS.items()
    ):

        result = analyze_group(
            group_name,
            transformations,
            clusters
        )


        results[
            group_name
        ] = result


    # --------------------------------------------------------
    # Main contrast:
    #
    # Encoding canonicalization improvement
    # minus change in untouched controls.
    # --------------------------------------------------------

    encoding_vs_control = (
        bootstrap_reduction_contrast(

            clusters,

            GROUPS[
                "encoding_only"
            ],

            GROUPS[
                "unchanged_controls"
            ],
        )
    )


    # --------------------------------------------------------
    # Console
    # --------------------------------------------------------

    print()
    print(
        "=" * 90
    )

    print(
        "PAIRED CLUSTER BOOTSTRAP — STRICT FPR"
    )

    print(
        "=" * 90
    )


    print(
        f"{'Group':<24}"
        f"{'V1 FPR':>12}"
        f"{'V2 FPR':>12}"
        f"{'Reduction':>14}"
        f"{'95% CI':>24}"
    )

    print(
        "-" * 86
    )


    for group_name in GROUPS:

        result = results[
            group_name
        ]


        lower, upper = (
            result[
                "bootstrap_95_ci"
            ]
        )


        ci = (
            f"[{percent(lower)}, "
            f"{percent(upper)}]"
        )


        print(
            f"{group_name:<24}"
            f"{percent(result['observed_v1_fpr']):>12}"
            f"{percent(result['observed_v2_fpr']):>12}"
            f"{percent(result['observed_fpr_reduction']):>14}"
            f"{ci:>24}"
        )


    print()
    print(
        "=" * 90
    )

    print(
        "ENCODING VS UNCHANGED-CONTROL CONTRAST"
    )

    print(
        "=" * 90
    )


    contrast = (
        encoding_vs_control[
            "observed_contrast"
        ]
    )

    lower, upper = (
        encoding_vs_control[
            "bootstrap_95_ci"
        ]
    )


    print(
        "Encoding FPR reduction minus "
        "unchanged-control reduction:"
    )

    print(
        f"Observed contrast: "
        f"{percent(contrast)}"
    )

    print(
        f"Bootstrap 95% CI: "
        f"[{percent(lower)}, "
        f"{percent(upper)}]"
    )

    print(
        "Bootstrap probability contrast > 0: "
        f"{encoding_vs_control['bootstrap_probability_positive'] * 100:.1f}%"
    )


    # --------------------------------------------------------
    # Save JSON
    # --------------------------------------------------------

    output = {

        "experiment":
            "AgentShield-ObfusBench",

        "analysis":
            "paired cluster bootstrap",

        "bootstrap_iterations":
            BOOTSTRAP_ITERATIONS,

        "random_seed":
            RANDOM_SEED,

        "cluster_unit":
            "SAFE base_id",

        "safe_base_clusters":
            len(clusters),

        "groups":
            results,

        "encoding_vs_unchanged_control":
            encoding_vs_control,

        "methodological_note":
            (
                "Bootstrap resampling is performed "
                "at the SAFE base-case level so that "
                "all transformations and replicates "
                "belonging to a base case remain "
                "clustered. Results remain exploratory "
                "because the benchmark contains only "
                "10 SAFE base-case clusters."
            ),
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
        "Saved to:"
    )

    print(
        OUTPUT_FILE
    )


if __name__ == "__main__":
    main()