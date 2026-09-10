import json
import re
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent

HOLDOUT_FILE = (
    PROJECT_ROOT
    / "dataset"
    / "holdout_base_cases_v1.jsonl"
)

BENCHMARK_FILE = (
    PROJECT_ROOT
    / "dataset"
    / "base_cases_v2.jsonl"
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


def normalize_text(text):
    return re.sub(
        r"\s+",
        " ",
        text.strip().lower()
    )


def main():

    holdout = load_jsonl(
        HOLDOUT_FILE
    )

    benchmark = load_jsonl(
        BENCHMARK_FILE
    )


    benchmark_map = {}

    for record in benchmark:

        normalized = normalize_text(
            record["text"]
        )

        benchmark_map[
            normalized
        ] = record


    found = 0


    for holdout_record in holdout:

        normalized = normalize_text(
            holdout_record["text"]
        )

        if normalized in benchmark_map:

            benchmark_record = (
                benchmark_map[
                    normalized
                ]
            )

            found += 1

            print(
                "=" * 78
            )

            print(
                f"HOLDOUT ID: "
                f"{holdout_record['id']}"
            )

            print(
                f"HOLDOUT CATEGORY: "
                f"{holdout_record['category']}"
            )

            print()

            print(
                "TEXT:"
            )

            print(
                holdout_record["text"]
            )

            print()

            print(
                f"BENCHMARK V2 ID: "
                f"{benchmark_record['id']}"
            )

            print(
                f"BENCHMARK V2 CATEGORY: "
                f"{benchmark_record['category']}"
            )

            print(
                "=" * 78
            )

            print()


    print(
        f"TOTAL OVERLAPS: {found}"
    )


if __name__ == "__main__":
    main()