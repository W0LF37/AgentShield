import hashlib
import json
import re
from collections import Counter
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent

HOLDOUT_FILE = (
    PROJECT_ROOT
    / "dataset"
    / "holdout_base_cases_v1.jsonl"
)

BENCHMARK_V2_BASE_FILE = (
    PROJECT_ROOT
    / "dataset"
    / "base_cases_v2.jsonl"
)

PILOT_BASE_FILE = (
    PROJECT_ROOT
    / "dataset"
    / "base_cases.jsonl"
)


EXPECTED_TOTAL = 200
EXPECTED_MALICIOUS = 100
EXPECTED_SAFE = 100

EXPECTED_PER_CATEGORY = 10

REQUIRED_FIELDS = {
    "id",
    "label",
    "category",
    "text",
    "source",
    "benchmark_version",
    "split",
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
                    f"Invalid JSON in {path.name} "
                    f"at line {line_number}: {error}"
                )

            records.append(record)

    return records


def normalize_text(text):
    text = text.strip().lower()

    text = re.sub(
        r"\s+",
        " ",
        text
    )

    return text


def sha256_file(path):
    digest = hashlib.sha256()

    with path.open("rb") as file:

        while True:
            chunk = file.read(
                1024 * 1024
            )

            if not chunk:
                break

            digest.update(chunk)

    return digest.hexdigest()


def main():
    errors = []
    warnings = []

    print("=" * 78)
    print("AgentShield-ObfusBench")
    print("Holdout v1 Validator")
    print("=" * 78)
    print()

    # ========================================================
    # File existence
    # ========================================================

    if not HOLDOUT_FILE.exists():
        raise FileNotFoundError(
            f"Holdout file not found:\n"
            f"{HOLDOUT_FILE}"
        )

    records = load_jsonl(
        HOLDOUT_FILE
    )

    print(
        f"Loaded holdout cases: "
        f"{len(records)}"
    )

    # ========================================================
    # Total
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
            - set(record.keys())
        )

        if missing:
            errors.append(
                f"Record {index} missing fields: "
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
        item
        for item, count in id_counts.items()
        if count > 1
    ]

    if duplicate_ids:
        errors.append(
            "Duplicate IDs: "
            + ", ".join(duplicate_ids)
        )

    # ========================================================
    # Exact normalized duplicate texts
    # ========================================================

    normalized_texts = [
        normalize_text(
            record.get("text", "")
        )
        for record in records
    ]

    text_counts = Counter(
        normalized_texts
    )

    duplicate_texts = [
        text
        for text, count in text_counts.items()
        if count > 1
    ]

    if duplicate_texts:
        errors.append(
            f"Found {len(duplicate_texts)} "
            f"duplicate normalized texts "
            f"inside holdout."
        )

    # ========================================================
    # Labels
    # ========================================================

    label_counts = Counter(
        record.get("label")
        for record in records
    )

    if label_counts.get(
        "MALICIOUS",
        0
    ) != EXPECTED_MALICIOUS:

        errors.append(
            f"Expected {EXPECTED_MALICIOUS} "
            f"MALICIOUS, found "
            f"{label_counts.get('MALICIOUS', 0)}."
        )

    if label_counts.get(
        "SAFE",
        0
    ) != EXPECTED_SAFE:

        errors.append(
            f"Expected {EXPECTED_SAFE} SAFE, "
            f"found "
            f"{label_counts.get('SAFE', 0)}."
        )

    invalid_labels = set(
        label_counts
    ) - {
        "MALICIOUS",
        "SAFE",
    }

    if invalid_labels:
        errors.append(
            f"Invalid labels: "
            f"{sorted(invalid_labels)}"
        )

    # ========================================================
    # Categories
    # ========================================================

    category_by_label = {
        "MALICIOUS": Counter(),
        "SAFE": Counter(),
    }

    for record in records:

        label = record.get("label")
        category = record.get("category")

        if label in category_by_label:
            category_by_label[
                label
            ][
                category
            ] += 1

    for label in [
        "MALICIOUS",
        "SAFE",
    ]:

        categories = (
            category_by_label[
                label
            ]
        )

        if len(categories) != 10:
            errors.append(
                f"{label}: expected 10 categories, "
                f"found {len(categories)}."
            )

        for category, count in categories.items():

            if count != EXPECTED_PER_CATEGORY:
                errors.append(
                    f"{label}/{category}: "
                    f"expected "
                    f"{EXPECTED_PER_CATEGORY}, "
                    f"found {count}."
                )

    # ========================================================
    # Metadata
    # ========================================================

    for record in records:

        record_id = record.get(
            "id"
        )

        if (
            record.get(
                "benchmark_version"
            )
            != "holdout_v1"
        ):
            errors.append(
                f"{record_id}: "
                f"benchmark_version must be "
                f"holdout_v1."
            )

        if (
            record.get(
                "split"
            )
            != "holdout"
        ):
            errors.append(
                f"{record_id}: "
                f"split must be holdout."
            )

        if (
            record.get(
                "source"
            )
            != "synthetic_curated_holdout"
        ):
            errors.append(
                f"{record_id}: "
                f"unexpected source value."
            )

    # ========================================================
    # Basic text sanity
    # ========================================================

    for record in records:

        text = record.get(
            "text",
            ""
        )

        if not isinstance(
            text,
            str
        ):

            errors.append(
                f"{record.get('id')}: "
                f"text is not a string."
            )

            continue

        if len(text.strip()) < 20:
            warnings.append(
                f"{record.get('id')}: "
                f"text shorter than 20 chars."
            )

        if len(text) > 1000:
            warnings.append(
                f"{record.get('id')}: "
                f"text longer than 1000 chars."
            )

    # ========================================================
    # Exact overlap with Benchmark v2 development set
    # ========================================================

    holdout_text_set = set(
        normalized_texts
    )

    overlap_v2 = set()

    if BENCHMARK_V2_BASE_FILE.exists():

        benchmark_v2_records = load_jsonl(
            BENCHMARK_V2_BASE_FILE
        )

        benchmark_v2_texts = {
            normalize_text(
                record.get(
                    "text",
                    ""
                )
            )
            for record
            in benchmark_v2_records
        }

        overlap_v2 = (
            holdout_text_set
            & benchmark_v2_texts
        )

        if overlap_v2:
            errors.append(
                f"Found {len(overlap_v2)} "
                f"exact normalized text overlaps "
                f"with base_cases_v2.jsonl."
            )

    else:
        warnings.append(
            "base_cases_v2.jsonl not found; "
            "could not check overlap."
        )

    # ========================================================
    # Exact overlap with Pilot
    # ========================================================

    overlap_pilot = set()

    if PILOT_BASE_FILE.exists():

        pilot_records = load_jsonl(
            PILOT_BASE_FILE
        )

        pilot_texts = {
            normalize_text(
                record.get(
                    "text",
                    ""
                )
            )
            for record
            in pilot_records
        }

        overlap_pilot = (
            holdout_text_set
            & pilot_texts
        )

        if overlap_pilot:
            errors.append(
                f"Found {len(overlap_pilot)} "
                f"exact normalized text overlaps "
                f"with pilot base_cases.jsonl."
            )

    else:
        warnings.append(
            "Pilot base_cases.jsonl not found; "
            "could not check overlap."
        )

    # ========================================================
    # SHA256
    # ========================================================

    file_hash = sha256_file(
        HOLDOUT_FILE
    )

    # ========================================================
    # Print distributions
    # ========================================================

    print()
    print("LABEL DISTRIBUTION")
    print("-" * 78)

    print(
        f"MALICIOUS: "
        f"{label_counts.get('MALICIOUS', 0)}"
    )

    print(
        f"SAFE:      "
        f"{label_counts.get('SAFE', 0)}"
    )

    print()
    print("MALICIOUS CATEGORIES")
    print("-" * 78)

    for category, count in sorted(
        category_by_label[
            "MALICIOUS"
        ].items()
    ):
        print(
            f"{category:<32}{count}"
        )

    print()
    print("SAFE CATEGORIES")
    print("-" * 78)

    for category, count in sorted(
        category_by_label[
            "SAFE"
        ].items()
    ):
        print(
            f"{category:<32}{count}"
        )

    print()
    print("OVERLAP CHECK")
    print("-" * 78)

    print(
        f"Exact overlap with Benchmark v2: "
        f"{len(overlap_v2)}"
    )

    print(
        f"Exact overlap with Pilot: "
        f"{len(overlap_pilot)}"
    )

    print()
    print("SHA256")
    print("-" * 78)

    print(
        file_hash
    )

    print()
    print("=" * 78)

    # ========================================================
    # Result
    # ========================================================

    if warnings:

        print(
            f"WARNINGS: "
            f"{len(warnings)}"
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

        print("=" * 78)

        for error in errors:
            print(
                f"  - {error}"
            )

        raise SystemExit(1)

    print(
        "VALIDATION PASSED"
    )

    print("=" * 78)

    print(
        "✓ 200 holdout base cases"
    )

    print(
        "✓ 100 MALICIOUS / 100 SAFE"
    )

    print(
        "✓ 10 categories per label"
    )

    print(
        "✓ 10 cases per category"
    )

    print(
        "✓ Unique IDs"
    )

    print(
        "✓ Unique normalized texts"
    )

    print(
        "✓ Holdout metadata valid"
    )

    print(
        "✓ No exact overlap with Benchmark v2"
    )

    print(
        "✓ No exact overlap with Pilot"
    )


if __name__ == "__main__":
    main()