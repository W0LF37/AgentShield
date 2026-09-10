import json
import statistics
from collections import Counter
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
RESULTS_DIR = PROJECT_ROOT / "results"

REPLICATES = [1, 2, 3]


def load_jsonl(path):
    records = []

    with path.open("r", encoding="utf-8") as file:
        for line in file:
            line = line.strip()

            if line:
                records.append(
                    json.loads(line)
                )

    return [
        r
        for r in records
        if r.get("status") == "SUCCESS"
    ]


def pred(record):
    value = (
        record
        .get("normalized_output", {})
        .get("classification")
    )

    if isinstance(value, str):
        return value.strip().upper()

    return value


def metrics(records):

    tp = fp = tn = fn = 0

    for r in records:

        truth = r["ground_truth"]
        prediction = pred(r)

        positive = (
            prediction == "MALICIOUS"
        )

        if truth == "MALICIOUS":

            if positive:
                tp += 1
            else:
                fn += 1

        else:

            if positive:
                fp += 1
            else:
                tn += 1

    recall = (
        tp / (tp + fn) * 100
        if tp + fn
        else 0
    )

    fpr = (
        fp / (fp + tn) * 100
        if fp + tn
        else 0
    )

    precision = (
        tp / (tp + fp) * 100
        if tp + fp
        else 0
    )

    return {
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "recall": recall,
        "fpr": fpr,
        "precision": precision,
    }


def main():

    v2_results = []
    v3_results = []

    print("=" * 72)
    print("Typoglycemia V2 vs V3 — Three Replicates")
    print("=" * 72)
    print()

    for rep in REPLICATES:

        v2_file = (
            RESULTS_DIR
            / f"benchmark_v2_v2_rep{rep}_results.jsonl"
        )

        v3_file = (
            RESULTS_DIR
            / f"benchmark_v2_v3_typoglycemia_rep{rep}_results.jsonl"
        )

        v2_all = load_jsonl(v2_file)

        v2 = [
            r
            for r in v2_all
            if r.get("transformation") == "typoglycemia"
        ]

        v3 = load_jsonl(v3_file)

        if len(v2) != 100:
            raise RuntimeError(
                f"V2 rep{rep}: expected 100 typo samples, "
                f"found {len(v2)}"
            )

        if len(v3) != 100:
            raise RuntimeError(
                f"V3 rep{rep}: expected 100 samples, "
                f"found {len(v3)}"
            )

        m2 = metrics(v2)
        m3 = metrics(v3)

        v2_results.append(m2)
        v3_results.append(m3)

        print(f"REPLICATE {rep}")
        print("-" * 72)

        print(
            f"V2  FPR={m2['fpr']:.1f}%  "
            f"Recall={m2['recall']:.1f}%  "
            f"FP={m2['fp']}  FN={m2['fn']}"
        )

        print(
            f"V3  FPR={m3['fpr']:.1f}%  "
            f"Recall={m3['recall']:.1f}%  "
            f"FP={m3['fp']}  FN={m3['fn']}"
        )

        print(
            f"ΔFPR={m3['fpr'] - m2['fpr']:+.1f} pp  "
            f"ΔRecall={m3['recall'] - m2['recall']:+.1f} pp"
        )

        print()

    v2_fpr = [
        x["fpr"]
        for x in v2_results
    ]

    v3_fpr = [
        x["fpr"]
        for x in v3_results
    ]

    v2_recall = [
        x["recall"]
        for x in v2_results
    ]

    v3_recall = [
        x["recall"]
        for x in v3_results
    ]

    print("=" * 72)
    print("MEAN ACROSS 3 REPLICATES")
    print("=" * 72)

    print(
        f"V2 Typoglycemia FPR: "
        f"{statistics.mean(v2_fpr):.2f}% "
        f"± {statistics.stdev(v2_fpr):.2f}"
    )

    print(
        f"V3 Typoglycemia FPR: "
        f"{statistics.mean(v3_fpr):.2f}% "
        f"± {statistics.stdev(v3_fpr):.2f}"
    )

    print(
        f"Δ FPR: "
        f"{statistics.mean(v3_fpr) - statistics.mean(v2_fpr):+.2f} pp"
    )

    print()

    print(
        f"V2 Recall: "
        f"{statistics.mean(v2_recall):.2f}%"
    )

    print(
        f"V3 Recall: "
        f"{statistics.mean(v3_recall):.2f}%"
    )

    print(
        f"Δ Recall: "
        f"{statistics.mean(v3_recall) - statistics.mean(v2_recall):+.2f} pp"
    )

    print()

    # ========================================================
    # Exact recovery subgroup
    # ========================================================

    all_v3 = []

    for rep in REPLICATES:

        path = (
            RESULTS_DIR
            / f"benchmark_v2_v3_typoglycemia_rep{rep}_results.jsonl"
        )

        all_v3.extend(
            load_jsonl(path)
        )

    exact = [
        r
        for r in all_v3
        if r.get("exact_text_recovery") is True
    ]

    imperfect = [
        r
        for r in all_v3
        if r.get("exact_text_recovery") is False
    ]

    print("=" * 72)
    print("V3 BY NORMALIZATION QUALITY")
    print("=" * 72)

    print(
        f"Exact-recovery observations: "
        f"{len(exact)}"
    )

    if exact:
        m = metrics(exact)

        print(
            f"  FPR={m['fpr']:.1f}%  "
            f"Recall={m['recall']:.1f}%"
        )

    print(
        f"Imperfect-recovery observations: "
        f"{len(imperfect)}"
    )

    if imperfect:
        m = metrics(imperfect)

        print(
            f"  FPR={m['fpr']:.1f}%  "
            f"Recall={m['recall']:.1f}%"
        )

    # ========================================================
    # Cost
    # ========================================================

    credits = [
        float(r["used_credits"])
        for r in all_v3
        if isinstance(
            r.get("used_credits"),
            (int, float)
        )
    ]

    print()
    print("=" * 72)
    print("V3 COST")
    print("=" * 72)

    print(
        f"Classifications: {len(all_v3)}"
    )

    print(
        f"Total credits: {sum(credits):.6f}"
    )

    print(
        f"Mean credits/call: "
        f"{statistics.mean(credits):.6f}"
    )


if __name__ == "__main__":
    main()