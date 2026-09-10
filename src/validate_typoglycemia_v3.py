import json
from collections import Counter
from pathlib import Path

from typoglycemia_normalizer import normalize_typoglycemia


PROJECT_ROOT = Path(__file__).resolve().parent.parent

BENCHMARK_FILE = (
    PROJECT_ROOT
    / "dataset"
    / "frozen_v2"
    / "benchmark_v2.jsonl"
)


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

    if not BENCHMARK_FILE.exists():
        raise FileNotFoundError(
            f"Frozen benchmark not found:\n"
            f"{BENCHMARK_FILE}"
        )

    records = load_jsonl(
        BENCHMARK_FILE
    )

    typo_records = [
        record
        for record in records
        if (
            record.get("transformation")
            == "typoglycemia"
        )
    ]

    if len(typo_records) != 100:
        raise RuntimeError(
            f"Expected 100 typoglycemia samples, "
            f"found {len(typo_records)}."
        )


    exact_recoveries = 0
    changed_count = 0
    unchanged_count = 0

    total_replacements = 0

    label_stats = Counter()

    failures = []


    for record in typo_records:

        transformed_text = record[
            "text"
        ]

        original_text = record[
            "original_text"
        ]

        result = normalize_typoglycemia(
            transformed_text
        )

        canonical_text = result[
            "canonical_text"
        ]

        changed = result[
            "changed"
        ]

        replacement_count = result[
            "replacement_count"
        ]


        total_replacements += (
            replacement_count
        )


        if changed:
            changed_count += 1
        else:
            unchanged_count += 1


        if canonical_text == original_text:

            exact_recoveries += 1

            label_stats[
                (
                    record["label"],
                    "exact"
                )
            ] += 1

        else:

            label_stats[
                (
                    record["label"],
                    "failed"
                )
            ] += 1

            failures.append({
                "sample_id":
                    record[
                        "sample_id"
                    ],

                "label":
                    record[
                        "label"
                    ],

                "original_text":
                    original_text,

                "typoglycemia_text":
                    transformed_text,

                "normalized_text":
                    canonical_text,

                "replacements":
                    result[
                        "replacements"
                    ],
            })


    exact_rate = (
        exact_recoveries
        / len(typo_records)
        * 100
    )


    print(
        "=" * 78
    )

    print(
        "AgentShield-ObfusBench"
    )

    print(
        "V3 Typoglycemia Normalizer Validation"
    )

    print(
        "=" * 78
    )

    print()

    print(
        f"Typoglycemia samples: "
        f"{len(typo_records)}"
    )

    print(
        f"Exact text recoveries: "
        f"{exact_recoveries}/100 "
        f"({exact_rate:.1f}%)"
    )

    print(
        f"Changed by normalizer: "
        f"{changed_count}/100"
    )

    print(
        f"Unchanged by normalizer: "
        f"{unchanged_count}/100"
    )

    print(
        f"Total word replacements: "
        f"{total_replacements}"
    )

    print()

    print(
        "BY LABEL"
    )

    print(
        "-" * 78
    )

    for label in [
        "MALICIOUS",
        "SAFE",
    ]:

        exact = label_stats[
            (
                label,
                "exact"
            )
        ]

        failed = label_stats[
            (
                label,
                "failed"
            )
        ]

        print(
            f"{label:<12} "
            f"exact={exact:<3} "
            f"failed={failed:<3}"
        )


    print()

    print(
        "=" * 78
    )

    if exact_recoveries == 100:

        print(
            "VALIDATION PASSED — "
            "100/100 EXACT RECOVERY"
        )

    else:

        print(
            "PARTIAL RECOVERY"
        )

        print(
            "=" * 78
        )

        print(
            f"{len(failures)} samples were "
            f"not recovered exactly."
        )

        print()

        print(
            "FIRST 10 FAILURES"
        )

        print(
            "-" * 78
        )

        for failure in failures[:10]:

            print()

            print(
                failure[
                    "sample_id"
                ]
            )

            print(
                "Original:"
            )

            print(
                failure[
                    "original_text"
                ]
            )

            print(
                "Typoglycemia:"
            )

            print(
                failure[
                    "typoglycemia_text"
                ]
            )

            print(
                "Normalized:"
            )

            print(
                failure[
                    "normalized_text"
                ]
            )

            print(
                "Replacements:"
            )

            for replacement in failure[
                "replacements"
            ]:

                print(
                    f"  "
                    f"{replacement['original']}"
                    f" -> "
                    f"{replacement['normalized']}"
                )


    print()

    print(
        "=" * 78
    )

    print(
        "NOTE: This validation used no API calls "
        "and consumed 0 credits."
    )


if __name__ == "__main__":
    main()