import json
import re
from pathlib import Path
from collections import defaultdict

from redteam_canonicalizer_v4 import canonicalize


# ============================================================
# Paths
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parent.parent

INPUT_FILE = (
    PROJECT_ROOT
    / "results"
    / "redteam_batch_discovery_results.jsonl"
)

SUMMARY_FILE = (
    PROJECT_ROOT
    / "results"
    / "redteam_canonicalizer_v4_validation_summary.json"
)

MISMATCH_FILE = (
    PROJECT_ROOT
    / "results"
    / "redteam_canonicalizer_v4_mismatches.jsonl"
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


def normalize_for_comparison(text):

    if text is None:
        return None

    return re.sub(
        r"\s+",
        " ",
        text.strip()
    )


def first_value(record, keys):

    for key in keys:

        value = record.get(key)

        if value is not None:
            return value

    return None


def get_semantic_text(record):

    return first_value(
        record,
        [
            "semantic_text",
            "original_text",
            "base_text",
            "source_text",
        ]
    )


def get_transformed_text(record):

    return first_value(
        record,
        [
            "transformed_text",
            "variant_text",
            "representation_text",
            "input_text",
            "text",
        ]
    )


def get_seed_id(record):

    return first_value(
        record,
        [
            "redteam_seed_id",
            "seed_id",
            "base_id",
            "id",
        ]
    )


def get_representation(record):

    """
    Red-Team discovery results currently store this field
    as "transformation".

    Older/newer files may use "representation".

    Support both names.
    """

    return first_value(
        record,
        [
            "representation",
            "transformation",
        ]
    )


# ============================================================
# Main
# ============================================================

def main():

    print("=" * 78)
    print("AgentShield Red-Team Lab")
    print("Canonicalizer V4 Validator")
    print("=" * 78)
    print()


    if not INPUT_FILE.exists():

        raise FileNotFoundError(
            f"Missing input file:\n"
            f"{INPUT_FILE}"
        )


    records = load_jsonl(
        INPUT_FILE
    )


    print(
        f"Raw records loaded: "
        f"{len(records)}"
    )

    print()


    stats = defaultdict(
        lambda: {
            "total": 0,
            "canonicalization_errors": 0,
            "exact_recovery": 0,
            "normalized_recovery": 0,
            "mismatch": 0,
        }
    )


    mismatches = []

    valid_records = 0


    for index, record in enumerate(
        records,
        start=1
    ):

        status = record.get(
            "status"
        )

        if (
            status is not None
            and status != "SUCCESS"
        ):
            continue


        representation = get_representation(
            record
        )

        semantic_text = get_semantic_text(
            record
        )

        transformed_text = get_transformed_text(
            record
        )

        seed_id = get_seed_id(
            record
        )


        if not representation:

            raise RuntimeError(
                f"Record {index} has no "
                f"representation/transformation.\n"
                f"Keys: {list(record.keys())}"
            )


        if semantic_text is None:

            raise RuntimeError(
                f"Record {index} has no semantic/original text.\n"
                f"Seed: {seed_id}\n"
                f"Keys: {list(record.keys())}"
            )


        if transformed_text is None:

            raise RuntimeError(
                f"Record {index} has no transformed text.\n"
                f"Seed: {seed_id}\n"
                f"Keys: {list(record.keys())}"
            )


        representation = (
            str(representation)
            .strip()
            .lower()
        )


        valid_records += 1

        bucket = stats[
            representation
        ]

        bucket[
            "total"
        ] += 1


        result = canonicalize(
            transformed_text,
            representation,
        )


        canonical_text = result.get(
            "canonical_text"
        )

        error = result.get(
            "error"
        )


        if error is not None:

            bucket[
                "canonicalization_errors"
            ] += 1


        exact_match = (
            canonical_text
            == semantic_text
        )


        normalized_match = (
            normalize_for_comparison(
                canonical_text
            )
            ==
            normalize_for_comparison(
                semantic_text
            )
        )


        if exact_match:

            bucket[
                "exact_recovery"
            ] += 1

        elif normalized_match:

            bucket[
                "normalized_recovery"
            ] += 1

        else:

            bucket[
                "mismatch"
            ] += 1

            mismatches.append({
                "record_index":
                    index,

                "seed_id":
                    seed_id,

                "representation":
                    representation,

                "semantic_text":
                    semantic_text,

                "transformed_text":
                    transformed_text,

                "canonical_text":
                    canonical_text,

                "error":
                    error,

                "method":
                    result.get(
                        "method"
                    ),

                "details":
                    result.get(
                        "details",
                        {}
                    ),
            })


    # ========================================================
    # Print per-representation results
    # ========================================================

    print(
        f"Successful records validated: "
        f"{valid_records}"
    )

    print()

    print("=" * 78)
    print("RECOVERY BY REPRESENTATION")
    print("=" * 78)
    print()


    header = (
        f"{'Representation':<20}"
        f"{'Total':>7}"
        f"{'Exact':>9}"
        f"{'Norm':>9}"
        f"{'Mismatch':>10}"
        f"{'Errors':>9}"
        f"{'Recovery':>11}"
    )

    print(
        header
    )

    print(
        "-" * len(header)
    )


    summary_by_representation = {}


    for representation in sorted(
        stats.keys()
    ):

        bucket = stats[
            representation
        ]

        total = bucket[
            "total"
        ]

        exact = bucket[
            "exact_recovery"
        ]

        normalized = bucket[
            "normalized_recovery"
        ]

        mismatch = bucket[
            "mismatch"
        ]

        errors = bucket[
            "canonicalization_errors"
        ]


        recovered = (
            exact
            + normalized
        )


        recovery_rate = (
            recovered
            / total
            * 100
            if total
            else 0.0
        )


        print(
            f"{representation:<20}"
            f"{total:>7}"
            f"{exact:>9}"
            f"{normalized:>9}"
            f"{mismatch:>10}"
            f"{errors:>9}"
            f"{recovery_rate:>10.1f}%"
        )


        summary_by_representation[
            representation
        ] = {
            **bucket,

            "recovered":
                recovered,

            "recovery_rate":
                recovery_rate,
        }


    # ========================================================
    # Overall
    # ========================================================

    total = sum(
        value[
            "total"
        ]
        for value
        in stats.values()
    )

    exact = sum(
        value[
            "exact_recovery"
        ]
        for value
        in stats.values()
    )

    normalized = sum(
        value[
            "normalized_recovery"
        ]
        for value
        in stats.values()
    )

    errors = sum(
        value[
            "canonicalization_errors"
        ]
        for value
        in stats.values()
    )

    mismatch_count = len(
        mismatches
    )

    recovered = (
        exact
        + normalized
    )

    recovery_rate = (
        recovered
        / total
        * 100
        if total
        else 0.0
    )


    print()

    print("=" * 78)
    print("OVERALL")
    print("=" * 78)

    print(
        f"Total validated:       "
        f"{total}"
    )

    print(
        f"Exact recovery:        "
        f"{exact}"
    )

    print(
        f"Whitespace-only diff:  "
        f"{normalized}"
    )

    print(
        f"True mismatches:       "
        f"{mismatch_count}"
    )

    print(
        f"Canonicalizer errors:  "
        f"{errors}"
    )

    print(
        f"Recovery rate:         "
        f"{recovery_rate:.2f}%"
    )


    # ========================================================
    # Save mismatches
    # ========================================================

    with MISMATCH_FILE.open(
        "w",
        encoding="utf-8"
    ) as file:

        for mismatch in mismatches:

            file.write(
                json.dumps(
                    mismatch,
                    ensure_ascii=False
                )
                + "\n"
            )


    # ========================================================
    # Save summary
    # ========================================================

    summary = {
        "experiment":
            "AgentShield Red-Team "
            "Canonicalizer V4 Validation",

        "input_records":
            len(records),

        "validated_records":
            total,

        "exact_recovery":
            exact,

        "normalized_recovery":
            normalized,

        "true_mismatches":
            mismatch_count,

        "canonicalization_errors":
            errors,

        "recovery_rate":
            recovery_rate,

        "by_representation":
            summary_by_representation,
    }


    with SUMMARY_FILE.open(
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            summary,
            file,
            ensure_ascii=False,
            indent=2
        )


    print()

    print(
        "Mismatch details:"
    )

    print(
        MISMATCH_FILE
    )

    print()

    print(
        "Summary:"
    )

    print(
        SUMMARY_FILE
    )

    print()


    # ========================================================
    # Validation gate
    # ========================================================

    print("=" * 78)

    if (
        mismatch_count == 0
        and errors == 0
    ):

        print(
            "VALIDATION PASSED"
        )

        print(
            "All Red-Team representations "
            "were successfully recovered."
        )

    else:

        print(
            "VALIDATION NEEDS REVIEW"
        )

        print(
            "Inspect mismatch file before "
            "running any V4 API experiment."
        )

    print("=" * 78)


if __name__ == "__main__":
    main()