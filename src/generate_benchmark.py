import json
from pathlib import Path

from transformations import TRANSFORMATIONS


PROJECT_ROOT = Path(__file__).resolve().parent.parent

INPUT_FILE = PROJECT_ROOT / "dataset" / "base_cases.jsonl"
OUTPUT_DIR = PROJECT_ROOT / "dataset" / "generated"
OUTPUT_FILE = OUTPUT_DIR / "benchmark_v1.jsonl"


def load_jsonl(path: Path):
    with path.open("r", encoding="utf-8") as file:
        for line in file:
            line = line.strip()

            if line:
                yield json.loads(line)


def generate_benchmark():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    generated_samples = []

    for case in load_jsonl(INPUT_FILE):
        for transformation_name, transformation_function in TRANSFORMATIONS.items():

            transformed_text = transformation_function(case["text"])

            sample = {
                "sample_id": f"{case['id']}_{transformation_name}",
                "base_id": case["id"],
                "label": case["label"],
                "category": case["category"],
                "transformation": transformation_name,
                "text": transformed_text
            }

            generated_samples.append(sample)

    with OUTPUT_FILE.open("w", encoding="utf-8") as file:
        for sample in generated_samples:
            file.write(
                json.dumps(sample, ensure_ascii=False) + "\n"
            )

    print(f"Generated {len(generated_samples)} samples.")
    print(f"Saved to: {OUTPUT_FILE}")


if __name__ == "__main__":
    generate_benchmark()