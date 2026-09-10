import json
from pathlib import Path

from canonicalizer import canonicalize


# ============================================================
# Paths
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parent.parent

BASE_CASES_FILE = (
    PROJECT_ROOT
    / "dataset"
    / "base_cases.jsonl"
)

BENCHMARK_FILE = (
    PROJECT_ROOT
    / "dataset"
    / "generated"
    / "benchmark_v1.jsonl"
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

        for line in file:

            line = line.strip()

            if line:
                records.append(
                    json.loads(line)
                )

    return records


# ============================================================
# Main validation
# ============================================================

def main():

    base_cases = load_jsonl(
        BASE_CASES_FILE
    )

    benchmark = load_jsonl(
        BENCHMARK_FILE
    )


    # Map:
    #
    # M01 -> original M01 text
    # M02 -> original M02 text
    # ...
    # S10 -> original S10 text

    original_texts = {
        case["id"]: case["text"]
        for case in base_cases
    }


    errors = []

    counts = {
        "plain": 0,
        "hex": 0,
        "base64": 0,
        "spaced": 0,
        "typoglycemia": 0,
    }


    for sample in benchmark:

        sample_id = sample[
            "sample_id"
        ]

        base_id = sample[
            "base_id"
        ]

        transformation = sample[
            "transformation"
        ]

        transformed_text = sample[
            "text"
        ]

        original_text = original_texts[
            base_id
        ]


        result = canonicalize(
            transformed_text
        )

        canonical_text = result[
            "canonical_text"
        ]

        detected = result[
            "detected_representation"
        ]

        changed = result[
            "changed"
        ]


        counts[
            transformation
        ] += 1


        # ====================================================
        # Reversible transformations
        # ====================================================

        if transformation in {
            "hex",
            "base64",
            "spaced",
        }:

            # It should detect the correct representation.
            if detected != transformation:

                errors.append(
                    (
                        sample_id,
                        f"Expected detection "
                        f"{transformation}, "
                        f"got {detected}"
                    )
                )


            # It should actually modify the input.
            if changed is not True:

                errors.append(
                    (
                        sample_id,
                        "Expected changed=True"
                    )
                )


            # Most important:
            # decoded text must exactly equal the base text.
            if canonical_text != original_text:

                errors.append(
                    (
                        sample_id,
                        "Canonical text does not "
                        "match original base text."
                    )
                )


        # ====================================================
        # Plain
        # ====================================================

        elif transformation == "plain":

            if changed is not False:

                errors.append(
                    (
                        sample_id,
                        "Plain text was modified."
                    )
                )

            if canonical_text != original_text:

                errors.append(
                    (
                        sample_id,
                        "Plain canonical text "
                        "does not equal original."
                    )
                )


        # ====================================================
        # Typoglycemia
        # ====================================================

        elif transformation == "typoglycemia":

            # We intentionally do not reverse this.
            if changed is not False:

                errors.append(
                    (
                        sample_id,
                        "Typoglycemia was "
                        "unexpectedly modified."
                    )
                )

            if canonical_text != transformed_text:

                errors.append(
                    (
                        sample_id,
                        "Typoglycemia should "
                        "pass through unchanged."
                    )
                )


    # ========================================================
    # Report
    # ========================================================

    print(
        f"Benchmark samples checked: "
        f"{len(benchmark)}"
    )


    print(
        "\nTransformations:"
    )

    for name, count in sorted(
        counts.items()
    ):
        print(
            f"  {name}: {count}"
        )


    if errors:

        print(
            f"\nFAIL: "
            f"{len(errors)} canonicalization errors."
        )

        for sample_id, message in errors:

            print(
                f"  {sample_id}: "
                f"{message}"
            )

        raise SystemExit(1)


    print(
        "\nPASS: canonicalizer validation successful."
    )

    print(
        "Hex, Base64, and spaced samples "
        "reconstruct their original base text."
    )

    print(
        "Plain and typoglycemia samples "
        "remain unchanged."
    )


if __name__ == "__main__":
    main()