import json
from collections import Counter, defaultdict
from pathlib import Path

from canonicalizer import canonicalize


PROJECT_ROOT = Path(__file__).resolve().parent.parent

BENCHMARK_FILE = (
    PROJECT_ROOT
    / "dataset"
    / "generated"
    / "benchmark_v2.jsonl"
)


EXPECTED_TOTAL = 500
EXPECTED_BASE_CASES = 100

EXPECTED_TRANSFORMATIONS = {
    "plain",
    "hex",
    "base64",
    "spaced",
    "typoglycemia",
}


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
                    f"Invalid JSON at line "
                    f"{line_number}: {error}"
                )

    return records


def main():

    errors = []
    warnings = []


    if not BENCHMARK_FILE.exists():

        raise FileNotFoundError(
            f"Benchmark not found:\n"
            f"{BENCHMARK_FILE}"
        )


    records = load_jsonl(
        BENCHMARK_FILE
    )


    print(
        "=" * 76
    )

    print(
        "AgentShield-ObfusBench "
        "Benchmark v2 Validator"
    )

    print(
        "=" * 76
    )

    print(
        f"Loaded samples: "
        f"{len(records)}"
    )

    print()


    # ========================================================
    # Total count
    # ========================================================

    if len(records) != EXPECTED_TOTAL:

        errors.append(
            f"Expected {EXPECTED_TOTAL} samples, "
            f"found {len(records)}."
        )


    # ========================================================
    # Unique sample IDs
    # ========================================================

    sample_ids = [
        record.get("sample_id")
        for record in records
    ]

    sample_id_counts = Counter(
        sample_ids
    )

    duplicate_sample_ids = [
        sample_id
        for sample_id, count
        in sample_id_counts.items()
        if count > 1
    ]


    if duplicate_sample_ids:

        errors.append(
            "Duplicate sample IDs: "
            + ", ".join(
                duplicate_sample_ids
            )
        )


    # ========================================================
    # Base cases
    # ========================================================

    by_base = defaultdict(
        list
    )


    for record in records:

        by_base[
            record.get("base_id")
        ].append(
            record
        )


    if len(by_base) != EXPECTED_BASE_CASES:

        errors.append(
            f"Expected {EXPECTED_BASE_CASES} "
            f"unique base IDs, "
            f"found {len(by_base)}."
        )


    # ========================================================
    # Every base case must have exactly 5 transformations
    # ========================================================

    for base_id, base_records in (
        by_base.items()
    ):

        transformations = [
            record.get(
                "transformation"
            )
            for record in base_records
        ]


        if len(base_records) != 5:

            errors.append(
                f"{base_id}: expected 5 samples, "
                f"found {len(base_records)}."
            )


        if set(transformations) != (
            EXPECTED_TRANSFORMATIONS
        ):

            errors.append(
                f"{base_id}: wrong transformation "
                f"set: {sorted(set(transformations))}"
            )


        if len(transformations) != len(
            set(transformations)
        ):

            errors.append(
                f"{base_id}: duplicate "
                f"transformation detected."
            )


        # ----------------------------------------------------
        # All variants must share same original text
        # ----------------------------------------------------

        original_texts = {
            record.get(
                "original_text"
            )
            for record in base_records
        }


        if len(original_texts) != 1:

            errors.append(
                f"{base_id}: variants do not share "
                f"the same original_text."
            )


        # ----------------------------------------------------
        # All variants must share same label/category
        # ----------------------------------------------------

        labels = {
            record.get("label")
            for record in base_records
        }

        categories = {
            record.get("category")
            for record in base_records
        }


        if len(labels) != 1:

            errors.append(
                f"{base_id}: inconsistent labels."
            )


        if len(categories) != 1:

            errors.append(
                f"{base_id}: inconsistent categories."
            )


    # ========================================================
    # Distribution
    # ========================================================

    label_counts = Counter(
        record.get("label")
        for record in records
    )

    transformation_counts = Counter(
        record.get("transformation")
        for record in records
    )


    if label_counts.get(
        "MALICIOUS",
        0
    ) != 250:

        errors.append(
            f"Expected 250 MALICIOUS samples, "
            f"found "
            f"{label_counts.get('MALICIOUS', 0)}."
        )


    if label_counts.get(
        "SAFE",
        0
    ) != 250:

        errors.append(
            f"Expected 250 SAFE samples, "
            f"found "
            f"{label_counts.get('SAFE', 0)}."
        )


    for transformation in (
        EXPECTED_TRANSFORMATIONS
    ):

        count = transformation_counts.get(
            transformation,
            0
        )

        if count != 100:

            errors.append(
                f"{transformation}: "
                f"expected 100 samples, "
                f"found {count}."
            )


    # ========================================================
    # Canonicalizer validation
    # ========================================================

    canonicalizer_counts = Counter()

    recovery_success = Counter()

    recovery_failures = []


    for record in records:

        transformation = (
            record[
                "transformation"
            ]
        )

        text = record[
            "text"
        ]

        original_text = record[
            "original_text"
        ]


        result = canonicalize(
            text
        )


        detected = result.get(
            "detected_representation"
        )

        canonical_text = result.get(
            "canonical_text"
        )

        changed = result.get(
            "changed"
        )


        canonicalizer_counts[
            (
                transformation,
                detected
            )
        ] += 1


        # ----------------------------------------------------
        # Hex/Base64/Spaced must recover original exactly
        # ----------------------------------------------------

        if transformation in {
            "hex",
            "base64",
            "spaced",
        }:

            if canonical_text == original_text:

                recovery_success[
                    transformation
                ] += 1

            else:

                recovery_failures.append(
                    record[
                        "sample_id"
                    ]
                )


            if not changed:

                errors.append(
                    f"{record['sample_id']}: "
                    f"canonicalizer should have "
                    f"changed the input."
                )


        # ----------------------------------------------------
        # Plain must remain unchanged
        # ----------------------------------------------------

        elif transformation == "plain":

            if canonical_text != text:

                errors.append(
                    f"{record['sample_id']}: "
                    f"plain text was modified."
                )


            if changed:

                errors.append(
                    f"{record['sample_id']}: "
                    f"plain incorrectly marked changed."
                )


        # ----------------------------------------------------
        # Typoglycemia intentionally remains unnormalized
        # ----------------------------------------------------

        elif transformation == "typoglycemia":

            if canonical_text != text:

                errors.append(
                    f"{record['sample_id']}: "
                    f"typoglycemia was unexpectedly "
                    f"modified."
                )


            if changed:

                errors.append(
                    f"{record['sample_id']}: "
                    f"typoglycemia incorrectly "
                    f"marked changed."
                )


    if recovery_failures:

        errors.append(
            f"Canonicalization failed to recover "
            f"original text for "
            f"{len(recovery_failures)} samples."
        )


    # ========================================================
    # Metadata
    # ========================================================

    for record in records:

        if (
            record.get(
                "benchmark_version"
            )
            != "v2"
        ):

            errors.append(
                f"{record.get('sample_id')}: "
                f"benchmark_version is not v2."
            )


    # ========================================================
    # Print summary
    # ========================================================

    print(
        "LABEL DISTRIBUTION"
    )

    print(
        "-" * 76
    )

    print(
        f"MALICIOUS: "
        f"{label_counts.get('MALICIOUS', 0)}"
    )

    print(
        f"SAFE:      "
        f"{label_counts.get('SAFE', 0)}"
    )


    print()
    print(
        "TRANSFORMATION DISTRIBUTION"
    )

    print(
        "-" * 76
    )


    for transformation in sorted(
        EXPECTED_TRANSFORMATIONS
    ):

        print(
            f"{transformation:<16}"
            f"{transformation_counts.get(transformation, 0)}"
        )


    print()
    print(
        "CANONICALIZATION RECOVERY"
    )

    print(
        "-" * 76
    )


    for transformation in [
        "hex",
        "base64",
        "spaced"
    ]:

        print(
            f"{transformation:<16}"
            f"{recovery_success[transformation]}"
            f"/100 exact recoveries"
        )


    print()
    print(
        "=" * 76
    )


    if warnings:

        print(
            f"WARNINGS: {len(warnings)}"
        )

        for warning in warnings:

            print(
                f"  - {warning}"
            )

        print()


    if errors:

        print(
            f"VALIDATION FAILED "
            f"({len(errors)} errors)"
        )

        print(
            "=" * 76
        )

        for error in errors:

            print(
                f"  - {error}"
            )

        raise SystemExit(1)


    print(
        "VALIDATION PASSED"
    )

    print(
        "=" * 76
    )

    print(
        "✓ 500 total samples"
    )

    print(
        "✓ 100 unique base cases"
    )

    print(
        "✓ 5 transformations per base case"
    )

    print(
        "✓ 250 MALICIOUS / 250 SAFE"
    )

    print(
        "✓ 100 samples per transformation"
    )

    print(
        "✓ Unique sample IDs"
    )

    print(
        "✓ Hex exact recovery: 100/100"
    )

    print(
        "✓ Base64 exact recovery: 100/100"
    )

    print(
        "✓ Spaced exact recovery: 100/100"
    )

    print(
        "✓ Plain remains unchanged"
    )

    print(
        "✓ Typoglycemia remains unchanged"
    )


if __name__ == "__main__":
    main()