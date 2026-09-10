import json
from pathlib import Path

from transformations import TRANSFORMATIONS


PROJECT_ROOT = Path(__file__).resolve().parent.parent

INPUT_FILE = (
    PROJECT_ROOT
    / "dataset"
    / "base_cases_v2.jsonl"
)

OUTPUT_DIR = (
    PROJECT_ROOT
    / "dataset"
    / "generated"
)

OUTPUT_FILE = (
    OUTPUT_DIR
    / "benchmark_v2.jsonl"
)


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


def main():
    base_cases = load_jsonl(
        INPUT_FILE
    )

    OUTPUT_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

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
                    "v2",
            }

            generated.append(
                sample
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

    print(
        "=" * 70
    )

    print(
        "AgentShield-ObfusBench "
        "Benchmark v2 Generator"
    )

    print(
        "=" * 70
    )

    print(
        f"Base cases: "
        f"{len(base_cases)}"
    )

    print(
        f"Transformations per case: "
        f"{len(TRANSFORMATIONS)}"
    )

    print(
        f"Generated samples: "
        f"{len(generated)}"
    )

    print()

    print(
        "Transformations:"
    )

    for name in TRANSFORMATIONS:
        print(
            f"  - {name}"
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