import json
from pathlib import Path


# ============================================================
# Paths
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parent.parent
RESULTS_DIR = PROJECT_ROOT / "results"

INPUT_FILE = (
    RESULTS_DIR
    / "redteam_failure_corpus.jsonl"
)

OUTPUT_FILE = (
    RESULTS_DIR
    / "redteam_failure_shortlist.jsonl"
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


def write_jsonl(path, records):

    with path.open(
        "w",
        encoding="utf-8"
    ) as file:

        for record in records:

            file.write(
                json.dumps(
                    record,
                    ensure_ascii=False
                )
                + "\n"
            )


def find_case(
    records,
    representation,
    failure_type,
    subtype=None,
    operational=None,
    excluded_seed_ids=None,
):

    if excluded_seed_ids is None:
        excluded_seed_ids = set()

    candidates = []

    for record in records:

        if (
            record.get("representation")
            != representation
        ):
            continue

        if (
            record.get("failure_type")
            != failure_type
        ):
            continue

        if (
            subtype is not None
            and record.get(
                "under_defense_subtype"
            ) != subtype
        ):
            continue

        if (
            operational is not None
            and bool(
                record.get(
                    "operational_failure"
                )
            ) != operational
        ):
            continue

        candidates.append(
            record
        )

    if not candidates:
        return None

    candidates.sort(
        key=lambda item: (
            item.get(
                "redteam_seed_id",
                ""
            ),
            item.get(
                "failure_case_id",
                ""
            ),
        )
    )

    # Prefer a seed not already used.
    for candidate in candidates:

        if (
            candidate.get(
                "redteam_seed_id"
            )
            not in excluded_seed_ids
        ):
            return candidate

    # Fallback if all candidates reuse seeds.
    return candidates[0]


# ============================================================
# Selection plan
# ============================================================

SELECTION_PLAN = [
    {
        "name":
            "Unicode operational malicious miss",

        "representation":
            "unicode_escape",

        "failure_type":
            "REPRESENTATION_INDUCED_UNDER_DEFENSE",

        "subtype":
            "OPERATIONAL_MISS",

        "operational":
            True,
    },

    {
        "name":
            "Unicode strict-only degradation",

        "representation":
            "unicode_escape",

        "failure_type":
            "REPRESENTATION_INDUCED_UNDER_DEFENSE",

        "subtype":
            "STRICT_ONLY_DEGRADATION",

        "operational":
            False,
    },

    {
        "name":
            "Unicode over-defense",

        "representation":
            "unicode_escape",

        "failure_type":
            "REPRESENTATION_INDUCED_OVER_DEFENSE",
    },

    {
        "name":
            "ROT13 over-defense",

        "representation":
            "rot13",

        "failure_type":
            "REPRESENTATION_INDUCED_OVER_DEFENSE",
    },

    {
        "name":
            "HTML entities over-defense",

        "representation":
            "html_entities",

        "failure_type":
            "REPRESENTATION_INDUCED_OVER_DEFENSE",
    },

    {
        "name":
            "URL percent over-defense",

        "representation":
            "url_percent",

        "failure_type":
            "REPRESENTATION_INDUCED_OVER_DEFENSE",
    },

    {
        "name":
            "Hex known failure",

        "representation":
            "hex",

        "failure_type":
            "REPRESENTATION_INDUCED_OVER_DEFENSE",
    },

    {
        "name":
            "Base64 known failure",

        "representation":
            "base64",

        "failure_type":
            "REPRESENTATION_INDUCED_OVER_DEFENSE",
    },
]


# ============================================================
# Main
# ============================================================

def main():

    print("=" * 78)
    print("AgentShield Red-Team Lab")
    print("Failure Case Shortlist Builder")
    print("=" * 78)
    print()

    if not INPUT_FILE.exists():
        raise FileNotFoundError(
            f"Missing corpus file:\n"
            f"{INPUT_FILE}"
        )

    records = load_jsonl(
        INPUT_FILE
    )

    print(
        f"Failure corpus loaded: "
        f"{len(records)} cases"
    )

    print()

    selected = []

    used_seed_ids = set()


    for index, spec in enumerate(
        SELECTION_PLAN,
        start=1
    ):

        case = find_case(
            records=records,
            representation=spec[
                "representation"
            ],
            failure_type=spec[
                "failure_type"
            ],
            subtype=spec.get(
                "subtype"
            ),
            operational=spec.get(
                "operational"
            ),
            excluded_seed_ids=(
                used_seed_ids
            ),
        )

        if case is None:
            raise RuntimeError(
                f"Could not find case for: "
                f"{spec['name']}"
            )

        selected_case = dict(
            case
        )

        selected_case[
            "shortlist_index"
        ] = index

        selected_case[
            "selection_reason"
        ] = spec[
            "name"
        ]

        selected.append(
            selected_case
        )

        used_seed_ids.add(
            case.get(
                "redteam_seed_id"
            )
        )


    write_jsonl(
        OUTPUT_FILE,
        selected
    )


    print("=" * 78)
    print("SELECTED FAILURE CASES")
    print("=" * 78)
    print()


    for case in selected:

        print(
            f"[{case['shortlist_index']}/8]"
        )

        print(
            f"Reason: "
            f"{case['selection_reason']}"
        )

        print(
            f"Case ID: "
            f"{case['failure_case_id']}"
        )

        print(
            f"Seed: "
            f"{case['redteam_seed_id']}"
        )

        print(
            f"Representation: "
            f"{case['representation']}"
        )

        print(
            f"Ground truth: "
            f"{case['ground_truth']}"
        )

        print(
            f"Plain: "
            f"{case['plain_classification']}"
        )

        print(
            f"Variant: "
            f"{case['variant_classification']}"
        )

        print(
            f"Failure: "
            f"{case['failure_type']}"
        )

        if case.get(
            "under_defense_subtype"
        ):
            print(
                f"Subtype: "
                f"{case['under_defense_subtype']}"
            )

        print("-" * 78)


    print()

    print(
        f"Selected cases: "
        f"{len(selected)}"
    )

    print(
        f"Unique seeds represented: "
        f"{len(set(
            case['redteam_seed_id']
            for case in selected
        ))}"
    )

    print()

    print(
        "Saved:"
    )

    print(
        OUTPUT_FILE
    )

    print()

    print("=" * 78)
    print("SHORTLIST COMPLETE")
    print("=" * 78)


if __name__ == "__main__":
    main()