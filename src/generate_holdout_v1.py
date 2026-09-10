import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path

from transformations import TRANSFORMATIONS


PROJECT_ROOT = Path(__file__).resolve().parent.parent

INPUT_FILE = (
    PROJECT_ROOT
    / "dataset"
    / "holdout_base_cases_v1.jsonl"
)

OUTPUT_DIR = (
    PROJECT_ROOT
    / "dataset"
    / "generated"
)

OUTPUT_FILE = (
    OUTPUT_DIR
    / "holdout_benchmark_v1.jsonl"
)


EXPECTED_TRANSFORMATIONS = {
    "plain",
    "hex",
    "base64",
    "spaced",
    "typoglycemia",
}


def sha256_file(path):
    digest = hashlib.sha256()

    with path.open("rb") as file:
        while True:
            chunk = file.read(1024 * 1024)

            if not chunk:
                break

            digest.update(chunk)

    return digest.hexdigest()


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

    if not INPUT_FILE.exists():
        raise FileNotFoundError(
            f"Holdout base file not found:\n"
            f"{INPUT_FILE}"
        )


    # ========================================================
    # Check transformation configuration
    # ========================================================

    if set(
        TRANSFORMATIONS.keys()
    ) != EXPECTED_TRANSFORMATIONS:

        raise RuntimeError(
            "Unexpected transformation set:\n"
            f"{sorted(TRANSFORMATIONS.keys())}"
        )


    # ========================================================
    # Load frozen candidate base set
    # ========================================================

    base_cases = load_jsonl(
        INPUT_FILE
    )


    if len(base_cases) != 200:
        raise RuntimeError(
            f"Expected 200 base cases, "
            f"found {len(base_cases)}."
        )


    label_counts = Counter(
        case["label"]
        for case in base_cases
    )


    if (
        label_counts.get("MALICIOUS", 0) != 100
        or label_counts.get("SAFE", 0) != 100
    ):
        raise RuntimeError(
            "Expected 100 MALICIOUS "
            "and 100 SAFE base cases."
        )


    base_ids = [
        case["id"]
        for case in base_cases
    ]


    if len(set(base_ids)) != 200:
        raise RuntimeError(
            "Duplicate base IDs detected."
        )


    base_sha256 = sha256_file(
        INPUT_FILE
    )


    # ========================================================
    # Generate transformed benchmark
    # ========================================================

    generated = []


    for case in base_cases:

        for transformation_name, function in (
            TRANSFORMATIONS.items()
        ):

            transformed_text = function(
                case["text"]
            )


            sample = {
                "sample_id":
                    f"{case['id']}_{transformation_name}",

                "base_id":
                    case["id"],

                "ground_truth":
                    case["label"],

                "label":
                    case["label"],

                "category":
                    case["category"],

                "transformation":
                    transformation_name,

                "text":
                    transformed_text,

                "original_text":
                    case["text"],

                "source":
                    case["source"],

                "benchmark_version":
                    "holdout_v1",

                "split":
                    "holdout",

                "holdout_base_sha256":
                    base_sha256,
            }


            generated.append(
                sample
            )


    # ========================================================
    # Internal validation BEFORE writing
    # ========================================================

    if len(generated) != 1000:
        raise RuntimeError(
            f"Expected 1000 generated samples, "
            f"found {len(generated)}."
        )


    sample_ids = [
        sample["sample_id"]
        for sample in generated
    ]


    if len(set(sample_ids)) != 1000:
        raise RuntimeError(
            "Duplicate sample IDs detected."
        )


    generated_label_counts = Counter(
        sample["label"]
        for sample in generated
    )


    if (
        generated_label_counts.get(
            "MALICIOUS",
            0
        ) != 500
        or generated_label_counts.get(
            "SAFE",
            0
        ) != 500
    ):
        raise RuntimeError(
            "Generated label distribution "
            "is incorrect."
        )


    transformation_counts = Counter(
        sample["transformation"]
        for sample in generated
    )


    for transformation in (
        EXPECTED_TRANSFORMATIONS
    ):

        if (
            transformation_counts[
                transformation
            ]
            != 200
        ):
            raise RuntimeError(
                f"{transformation}: expected "
                f"200 samples, found "
                f"{transformation_counts[transformation]}."
            )


    by_base = defaultdict(list)


    for sample in generated:
        by_base[
            sample["base_id"]
        ].append(
            sample
        )


    if len(by_base) != 200:
        raise RuntimeError(
            f"Expected 200 unique base IDs, "
            f"found {len(by_base)}."
        )


    for base_id, samples in by_base.items():

        if len(samples) != 5:
            raise RuntimeError(
                f"{base_id}: expected "
                f"5 transformations."
            )


        transforms = {
            sample["transformation"]
            for sample in samples
        }


        if transforms != EXPECTED_TRANSFORMATIONS:
            raise RuntimeError(
                f"{base_id}: invalid "
                f"transformation set."
            )


    # ========================================================
    # Save
    # ========================================================

    OUTPUT_DIR.mkdir(
        parents=True,
        exist_ok=True
    )


    with OUTPUT_FILE.open(
        "w",
        encoding="utf-8"
    ) as file:

        for sample in generated:

            file.write(
                json.dumps(
                    sample,
                    ensure_ascii=False
                )
                + "\n"
            )


    output_sha256 = sha256_file(
        OUTPUT_FILE
    )


    # ========================================================
    # Summary
    # ========================================================

    print("=" * 78)

    print(
        "AgentShield-ObfusBench"
    )

    print(
        "Holdout v1 Generator"
    )

    print("=" * 78)

    print()

    print(
        f"Base cases: "
        f"{len(base_cases)}"
    )

    print(
        f"MALICIOUS base cases: "
        f"{label_counts['MALICIOUS']}"
    )

    print(
        f"SAFE base cases: "
        f"{label_counts['SAFE']}"
    )

    print()

    print(
        f"Transformations per base: "
        f"{len(TRANSFORMATIONS)}"
    )

    print(
        f"Generated samples: "
        f"{len(generated)}"
    )

    print()

    print(
        "TRANSFORMATIONS"
    )

    print("-" * 78)


    for transformation in sorted(
        EXPECTED_TRANSFORMATIONS
    ):

        print(
            f"{transformation:<18}"
            f"{transformation_counts[transformation]}"
        )


    print()
    print(
        "LABEL DISTRIBUTION"
    )

    print("-" * 78)

    print(
        f"MALICIOUS: "
        f"{generated_label_counts['MALICIOUS']}"
    )

    print(
        f"SAFE:      "
        f"{generated_label_counts['SAFE']}"
    )

    print()

    print(
        "HOLDOUT BASE SHA256"
    )

    print("-" * 78)

    print(
        base_sha256
    )

    print()

    print(
        "GENERATED BENCHMARK SHA256"
    )

    print("-" * 78)

    print(
        output_sha256
    )

    print()

    print(
        "Saved to:"
    )

    print(
        OUTPUT_FILE
    )

    print()

    print("=" * 78)

    print(
        "GENERATION + STRUCTURAL VALIDATION PASSED"
    )

    print("=" * 78)

    print(
        "✓ 200 independent holdout base cases"
    )

    print(
        "✓ 1000 transformed samples"
    )

    print(
        "✓ 500 MALICIOUS / 500 SAFE"
    )

    print(
        "✓ 200 samples per transformation"
    )

    print(
        "✓ 5 transformations per base case"
    )

    print(
        "✓ Unique sample IDs"
    )


if __name__ == "__main__":
    main()