import json
import re
from collections import Counter
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent

DATASET_DIR = PROJECT_ROOT / "dataset"

V2_FILE = DATASET_DIR / "base_cases_v2.jsonl"

# Pilot file — optional check for exact overlap
PILOT_FILE = DATASET_DIR / "base_cases.jsonl"


EXPECTED_TOTAL = 100

EXPECTED_LABEL_COUNTS = {
    "MALICIOUS": 50,
    "SAFE": 50,
}

EXPECTED_CASES_PER_CATEGORY = 5

REQUIRED_FIELDS = {
    "id",
    "label",
    "category",
    "text",
    "source",
    "benchmark_version",
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
                record = json.loads(line)

            except json.JSONDecodeError as error:

                raise RuntimeError(
                    f"Invalid JSON on line "
                    f"{line_number}: {error}"
                )

            records.append(record)

    return records


def normalize_text(text):

    text = text.lower().strip()

    text = re.sub(
        r"\s+",
        " ",
        text
    )

    return text


def main():

    errors = []
    warnings = []


    # ========================================================
    # File exists
    # ========================================================

    if not V2_FILE.exists():

        raise FileNotFoundError(
            f"Could not find:\n{V2_FILE}"
        )


    records = load_jsonl(
        V2_FILE
    )


    print(
        "=" * 72
    )

    print(
        "AgentShield-ObfusBench "
        "Benchmark v2 Base Dataset Validator"
    )

    print(
        "=" * 72
    )

    print(
        f"File: {V2_FILE}"
    )

    print(
        f"Loaded records: {len(records)}"
    )

    print()


    # ========================================================
    # Total count
    # ========================================================

    if len(records) != EXPECTED_TOTAL:

        errors.append(
            f"Expected {EXPECTED_TOTAL} records, "
            f"found {len(records)}."
        )


    # ========================================================
    # Required fields
    # ========================================================

    for index, record in enumerate(
        records,
        start=1
    ):

        missing = (
            REQUIRED_FIELDS
            - set(record)
        )

        if missing:

            errors.append(
                f"Record #{index} missing fields: "
                f"{sorted(missing)}"
            )


    # ========================================================
    # IDs
    # ========================================================

    ids = [
        record.get("id")
        for record in records
    ]

    id_counts = Counter(ids)

    duplicate_ids = [
        case_id
        for case_id, count
        in id_counts.items()
        if count > 1
    ]


    if duplicate_ids:

        errors.append(
            "Duplicate IDs: "
            + ", ".join(
                str(x)
                for x in duplicate_ids
            )
        )


    # ========================================================
    # Labels
    # ========================================================

    label_counts = Counter(

        record.get("label")
        for record in records
    )


    for label, expected in (
        EXPECTED_LABEL_COUNTS.items()
    ):

        actual = label_counts.get(
            label,
            0
        )

        if actual != expected:

            errors.append(
                f"{label}: expected "
                f"{expected}, found {actual}."
            )


    invalid_labels = (

        set(label_counts)
        - set(EXPECTED_LABEL_COUNTS)
    )


    if invalid_labels:

        errors.append(
            "Invalid labels: "
            + ", ".join(
                str(x)
                for x in invalid_labels
            )
        )


    # ========================================================
    # Category balance
    # ========================================================

    category_counts = Counter(

        (
            record.get("label"),
            record.get("category")
        )

        for record in records
    )


    for (
        label,
        category
    ), count in sorted(
        category_counts.items()
    ):

        if count != EXPECTED_CASES_PER_CATEGORY:

            errors.append(
                f"Category imbalance: "
                f"{label}/{category} "
                f"has {count} cases; "
                f"expected "
                f"{EXPECTED_CASES_PER_CATEGORY}."
            )


    malicious_categories = {
        record.get("category")
        for record in records
        if record.get("label") == "MALICIOUS"
    }

    safe_categories = {
        record.get("category")
        for record in records
        if record.get("label") == "SAFE"
    }


    if len(malicious_categories) != 10:

        errors.append(
            "Expected 10 MALICIOUS categories, "
            f"found {len(malicious_categories)}."
        )


    if len(safe_categories) != 10:

        errors.append(
            "Expected 10 SAFE categories, "
            f"found {len(safe_categories)}."
        )


    # ========================================================
    # Text quality basics
    # ========================================================

    normalized_texts = [

        normalize_text(
            record.get(
                "text",
                ""
            )
        )

        for record in records
    ]


    text_counts = Counter(
        normalized_texts
    )


    duplicate_texts = [

        text
        for text, count
        in text_counts.items()
        if count > 1
    ]


    if duplicate_texts:

        errors.append(
            f"Found {len(duplicate_texts)} "
            f"duplicate normalized texts."
        )


    for record in records:

        text = record.get(
            "text",
            ""
        ).strip()


        if len(text) < 20:

            warnings.append(
                f"{record.get('id')}: "
                f"very short text "
                f"({len(text)} chars)."
            )


        if len(text) > 1000:

            warnings.append(
                f"{record.get('id')}: "
                f"very long text "
                f"({len(text)} chars)."
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
                f"{record.get('id')}: "
                f"benchmark_version is not v2."
            )


        if not record.get(
            "source"
        ):

            errors.append(
                f"{record.get('id')}: "
                f"source is empty."
            )


    # ========================================================
    # Pilot overlap check
    # ========================================================

    pilot_overlap = []


    if PILOT_FILE.exists():

        pilot_records = load_jsonl(
            PILOT_FILE
        )

        pilot_texts = {

            normalize_text(
                record.get(
                    "text",
                    ""
                )
            )

            for record in pilot_records
        }


        for record in records:

            normalized = normalize_text(
                record.get(
                    "text",
                    ""
                )
            )

            if normalized in pilot_texts:

                pilot_overlap.append(
                    record.get("id")
                )


        if pilot_overlap:

            errors.append(
                "Exact text overlap with pilot set: "
                + ", ".join(
                    pilot_overlap
                )
            )


    # ========================================================
    # Print distribution
    # ========================================================

    print(
        "LABEL DISTRIBUTION"
    )

    print(
        "-" * 72
    )

    for label in [
        "MALICIOUS",
        "SAFE"
    ]:

        print(
            f"{label:<12}: "
            f"{label_counts.get(label, 0)}"
        )


    print()
    print(
        "CATEGORY DISTRIBUTION"
    )

    print(
        "-" * 72
    )


    for label in [
        "MALICIOUS",
        "SAFE"
    ]:

        print(
            f"\n{label}"
        )

        categories = sorted(

            (
                category,
                count
            )

            for (
                category_label,
                category
            ), count
            in category_counts.items()

            if category_label == label
        )


        for category, count in categories:

            print(
                f"  {category:<34} "
                f"{count}"
            )


    print()
    print(
        "PILOT OVERLAP"
    )

    print(
        "-" * 72
    )

    if PILOT_FILE.exists():

        print(
            f"Exact overlaps: "
            f"{len(pilot_overlap)}"
        )

    else:

        print(
            "Pilot file not found — "
            "overlap check skipped."
        )


    # ========================================================
    # Final status
    # ========================================================

    print()
    print(
        "=" * 72
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
            "=" * 72
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
        "=" * 72
    )

    print(
        "✓ 100 base cases"
    )

    print(
        "✓ 50 MALICIOUS / 50 SAFE"
    )

    print(
        "✓ Unique IDs"
    )

    print(
        "✓ Unique normalized texts"
    )

    print(
        "✓ Balanced categories"
    )

    print(
        "✓ Required metadata present"
    )

    if PILOT_FILE.exists():

        print(
            "✓ No exact pilot overlap"
        )


if __name__ == "__main__":
    main()