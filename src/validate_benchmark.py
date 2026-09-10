import json
from collections import Counter
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent

BENCHMARK_FILE = (
    PROJECT_ROOT
    / "dataset"
    / "generated"
    / "benchmark_v1.jsonl"
)


REQUIRED_FIELDS = {
    "sample_id",
    "base_id",
    "label",
    "category",
    "transformation",
    "text",
}

EXPECTED_TRANSFORMATIONS = {
    "plain",
    "hex",
    "base64",
    "spaced",
    "typoglycemia",
}


def load_jsonl(path):
    records = []

    with path.open("r", encoding="utf-8") as file:
        for line_number, line in enumerate(file, start=1):
            line = line.strip()

            if not line:
                continue

            try:
                records.append(json.loads(line))

            except json.JSONDecodeError as error:
                raise RuntimeError(
                    f"Invalid JSON on line {line_number}: {error}"
                )

    return records


def main():
    samples = load_jsonl(BENCHMARK_FILE)

    print(f"Total samples: {len(samples)}")

    # --------------------------------------------------------
    # Required fields
    # --------------------------------------------------------

    for sample in samples:
        missing = REQUIRED_FIELDS - sample.keys()

        if missing:
            raise RuntimeError(
                f"{sample.get('sample_id')} "
                f"is missing fields: {missing}"
            )


    # --------------------------------------------------------
    # Duplicate IDs
    # --------------------------------------------------------

    sample_ids = [
        sample["sample_id"]
        for sample in samples
    ]

    duplicates = [
        sample_id
        for sample_id, count
        in Counter(sample_ids).items()
        if count > 1
    ]

    if duplicates:
        raise RuntimeError(
            f"Duplicate sample IDs: {duplicates}"
        )


    # --------------------------------------------------------
    # Distribution
    # --------------------------------------------------------

    labels = Counter(
        sample["label"]
        for sample in samples
    )

    transformations = Counter(
        sample["transformation"]
        for sample in samples
    )

    base_ids = Counter(
        sample["base_id"]
        for sample in samples
    )

    print("\nLabels:")
    for label, count in sorted(labels.items()):
        print(f"  {label}: {count}")

    print("\nTransformations:")
    for transformation, count in sorted(
        transformations.items()
    ):
        print(
            f"  {transformation}: {count}"
        )

    print(
        f"\nUnique base cases: "
        f"{len(base_ids)}"
    )


    # --------------------------------------------------------
    # Expected benchmark structure
    # --------------------------------------------------------

    assert len(samples) == 100, (
        "Expected exactly 100 samples."
    )

    assert labels["MALICIOUS"] == 50, (
        "Expected 50 MALICIOUS samples."
    )

    assert labels["SAFE"] == 50, (
        "Expected 50 SAFE samples."
    )

    assert set(transformations) == (
        EXPECTED_TRANSFORMATIONS
    ), (
        "Unexpected transformation set."
    )

    for transformation in (
        EXPECTED_TRANSFORMATIONS
    ):
        assert transformations[
            transformation
        ] == 20, (
            f"Expected 20 samples for "
            f"{transformation}."
        )

    assert len(base_ids) == 20, (
        "Expected 20 unique base cases."
    )

    for base_id, count in base_ids.items():
        assert count == 5, (
            f"{base_id} has {count} variants "
            f"instead of 5."
        )


    print(
        "\nPASS: benchmark structure is valid."
    )

    print(
        "The dataset is ready for the "
        "official V1 experiment."
    )


if __name__ == "__main__":
    main()