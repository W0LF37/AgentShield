import os
import re
import json
import time
import base64
import hashlib
import argparse
from pathlib import Path

import requests


# ============================================================
# Configuration
# ============================================================

GEMINI_AGENT_ID = "6aa16caa684cccba45e9b7e0"

PROJECT_ROOT = Path(__file__).resolve().parent.parent

BENCHMARK_FILE = (
    PROJECT_ROOT
    / "dataset"
    / "frozen_holdout_v1"
    / "holdout_benchmark_v1.jsonl"
)

RESULTS_DIR = PROJECT_ROOT / "results"

DIRECT_FILE = (
    RESULTS_DIR
    / "gemini_crossmodel_direct_rep1_results.jsonl"
)

CANON_FILE = (
    RESULTS_DIR
    / "gemini_crossmodel_canonicalized_rep1_results.jsonl"
)

TRANSFORMATIONS = {
    "plain",
    "hex",
    "base64",
}

API_KEY = os.getenv("AIXPLAIN_API_KEY")

if not API_KEY:
    raise RuntimeError(
        "AIXPLAIN_API_KEY environment variable is not set."
    )

HEADERS = {
    "x-api-key": API_KEY,
    "Content-Type": "application/json",
}


# ============================================================
# Canonicalizer
# Same strict logic used for representation normalization
# ============================================================

HEX_RE = re.compile(
    r"^(?:[0-9A-Fa-f]{2})(?: [0-9A-Fa-f]{2})+$"
)

BASE64_RE = re.compile(
    r"^[A-Za-z0-9+/]+={0,2}$"
)


def printable_text(text):
    if not text:
        return False

    return all(
        char.isprintable()
        or char in "\n\r\t"
        for char in text
    )


def canonicalize(text):

    # Hex
    if HEX_RE.fullmatch(text):

        try:
            raw = bytes.fromhex(text)
            decoded = raw.decode("utf-8")

            if printable_text(decoded):
                return decoded, "hex"

        except Exception:
            pass

    # Base64
    if (
        len(text) >= 16
        and len(text) % 4 == 0
        and BASE64_RE.fullmatch(text)
    ):

        try:
            raw = base64.b64decode(
                text,
                validate=True
            )

            decoded = raw.decode("utf-8")

            if printable_text(decoded):
                return decoded, "base64"

        except Exception:
            pass

    return text, "plain"


# ============================================================
# Dataset
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


def get_input_text(record):

    possible_keys = [
        "transformed_text",
        "input_text",
        "text",
        "prompt",
        "input",
    ]

    for key in possible_keys:

        value = record.get(key)

        if isinstance(value, str):
            return value

    raise RuntimeError(
        f"Could not find text field for "
        f"sample {record.get('sample_id')}"
    )


def sha256_file(path):

    digest = hashlib.sha256()

    with path.open("rb") as file:

        while True:

            chunk = file.read(1024 * 1024)

            if not chunk:
                break

            digest.update(chunk)

    return digest.hexdigest()


# ============================================================
# Resume
# ============================================================

def successful_ids(path):

    ids = set()

    if not path.exists():
        return ids

    with path.open(
        "r",
        encoding="utf-8"
    ) as file:

        for line in file:

            line = line.strip()

            if not line:
                continue

            try:
                record = json.loads(line)

                if (
                    record.get("status")
                    == "SUCCESS"
                ):
                    ids.add(
                        record["sample_id"]
                    )

            except Exception:
                pass

    return ids


def append_result(path, record):

    RESULTS_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    with path.open(
        "a",
        encoding="utf-8"
    ) as file:

        file.write(
            json.dumps(
                record,
                ensure_ascii=False
            )
            + "\n"
        )


# ============================================================
# Output parsing
# ============================================================

def parse_output(output):

    if isinstance(output, dict):
        parsed = output

    elif isinstance(output, str):

        text = output.strip()

        if text.startswith("```"):
            text = re.sub(
                r"^```(?:json)?",
                "",
                text
            )

            text = re.sub(
                r"```$",
                "",
                text
            )

            text = text.strip()

        try:
            parsed = json.loads(text)

        except Exception:
            return None

    else:
        return None


    classification = parsed.get(
        "classification"
    )

    if isinstance(
        classification,
        str
    ):
        classification = (
            classification
            .strip()
            .upper()
        )

    if classification not in {
        "SAFE",
        "SUSPICIOUS",
        "MALICIOUS",
    }:
        return None

    parsed[
        "classification"
    ] = classification

    return parsed


# ============================================================
# aiXplain execution
# ============================================================

def execute_agent(query):

    run_url = (
        "https://platform-api.aixplain.com"
        f"/v2/agents/{GEMINI_AGENT_ID}/run"
    )

    response = requests.post(
        run_url,
        headers=HEADERS,
        json={
            "query": query
        },
        timeout=60,
    )

    response.raise_for_status()

    start = response.json()

    request_id = start.get(
        "requestId"
    )

    poll_url = start.get(
        "data"
    )

    if not poll_url:
        raise RuntimeError(
            f"No polling URL: {start}"
        )


    deadline = (
        time.time()
        + 300
    )


    while time.time() < deadline:

        response = requests.get(
            poll_url,
            headers=HEADERS,
            timeout=60,
        )

        response.raise_for_status()

        result = response.json()

        if result.get("completed"):

            return (
                request_id,
                result
            )

        time.sleep(2)


    raise TimeoutError(
        "Agent execution timed out."
    )


def classify_with_retries(
    text,
    max_attempts=3
):

    last_result = None
    last_request_id = None


    for attempt in range(
        1,
        max_attempts + 1
    ):

        try:

            request_id, result = (
                execute_agent(text)
            )

            last_result = result
            last_request_id = request_id

            status = result.get(
                "status"
            )

            data = result.get(
                "data",
                {}
            )

            output = data.get(
                "output"
            )

            parsed = parse_output(
                output
            )


            if (
                status == "SUCCESS"
                and parsed is not None
            ):

                return {
                    "status": "SUCCESS",
                    "request_id":
                        request_id,

                    "normalized_output":
                        parsed,

                    "raw_output":
                        output,

                    "used_credits":
                        data.get(
                            "usedCredits",
                            0
                        ),

                    "runtime_seconds":
                        data.get(
                            "runTime"
                        ),

                    "attempts":
                        attempt,
                }


        except Exception as error:

            last_result = {
                "local_error":
                    str(error)
            }


        if attempt < max_attempts:
            time.sleep(2)


    return {
        "status": "FAILED",
        "request_id":
            last_request_id,

        "normalized_output":
            None,

        "raw_output":
            (
                last_result
                if last_result
                else None
            ),

        "used_credits": 0,

        "runtime_seconds": None,

        "attempts":
            max_attempts,
    }


# ============================================================
# Main
# ============================================================

def main():

    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help=(
            "Process only the first N "
            "filtered samples."
        ),
    )

    args = parser.parse_args()


    benchmark_hash = sha256_file(
        BENCHMARK_FILE
    )

    records = load_jsonl(
        BENCHMARK_FILE
    )


    filtered = [
        record
        for record in records
        if record.get(
            "transformation"
        )
        in TRANSFORMATIONS
    ]


    if len(filtered) != 600:

        raise RuntimeError(
            f"Expected 600 focused samples, "
            f"found {len(filtered)}."
        )


    if args.limit is not None:
        filtered = filtered[
            :args.limit
        ]


    direct_done = successful_ids(
        DIRECT_FILE
    )

    canon_done = successful_ids(
        CANON_FILE
    )


    print("=" * 78)

    print(
        "AgentShield Cross-Model Validation"
    )

    print(
        "Gemini 2.5 Pro"
    )

    print("=" * 78)

    print(
        f"Benchmark SHA256: "
        f"{benchmark_hash}"
    )

    print(
        f"Focused samples this run: "
        f"{len(filtered)}"
    )

    print(
        "Transformations: "
        "plain, hex, base64"
    )

    print()

    print(
        f"Already complete — Direct: "
        f"{len(direct_done)}"
    )

    print(
        f"Already complete — Canonicalized: "
        f"{len(canon_done)}"
    )

    print()


    run_direct_credits = 0.0
    run_canon_credits = 0.0


    for index, record in enumerate(
        filtered,
        start=1
    ):

        sample_id = record[
            "sample_id"
        ]

        ground_truth = record[
            "ground_truth"
        ]

        transformation = record[
            "transformation"
        ]

        raw_text = get_input_text(
            record
        )

        canonical_text, detected = (
            canonicalize(
                raw_text
            )
        )


        print(
            f"[{index}/{len(filtered)}] "
            f"{sample_id} | "
            f"{ground_truth} | "
            f"{transformation}"
        )


        # ====================================================
        # V1 — Direct
        # ====================================================

        if sample_id in direct_done:

            print(
                "  Direct: SKIP"
            )

        else:

            result = (
                classify_with_retries(
                    raw_text
                )
            )

            output_record = {
                "sample_id":
                    sample_id,

                "base_id":
                    record.get(
                        "base_id"
                    ),

                "ground_truth":
                    ground_truth,

                "category":
                    record.get(
                        "category"
                    ),

                "transformation":
                    transformation,

                "pipeline":
                    "gemini_direct",

                "benchmark_sha256":
                    benchmark_hash,

                **result,
            }


            append_result(
                DIRECT_FILE,
                output_record
            )


            credits = float(
                result.get(
                    "used_credits",
                    0
                )
                or 0
            )

            run_direct_credits += (
                credits
            )


            prediction = None

            if result.get(
                "normalized_output"
            ):
                prediction = (
                    result[
                        "normalized_output"
                    ].get(
                        "classification"
                    )
                )


            print(
                f"  Direct: "
                f"{result['status']} | "
                f"{prediction} | "
                f"{credits:.6f}"
            )


        # ====================================================
        # V2 — Canonicalized locally
        # ====================================================

        if sample_id in canon_done:

            print(
                "  Canon:  SKIP"
            )

        else:

            result = (
                classify_with_retries(
                    canonical_text
                )
            )


            output_record = {
                "sample_id":
                    sample_id,

                "base_id":
                    record.get(
                        "base_id"
                    ),

                "ground_truth":
                    ground_truth,

                "category":
                    record.get(
                        "category"
                    ),

                "transformation":
                    transformation,

                "pipeline":
                    "gemini_canonicalized",

                "detected_representation":
                    detected,

                "canonicalization_changed":
                    int(
                        canonical_text
                        != raw_text
                    ),

                "benchmark_sha256":
                    benchmark_hash,

                **result,
            }


            append_result(
                CANON_FILE,
                output_record
            )


            credits = float(
                result.get(
                    "used_credits",
                    0
                )
                or 0
            )

            run_canon_credits += (
                credits
            )


            prediction = None

            if result.get(
                "normalized_output"
            ):
                prediction = (
                    result[
                        "normalized_output"
                    ].get(
                        "classification"
                    )
                )


            print(
                f"  Canon:  "
                f"{result['status']} | "
                f"{prediction} | "
                f"{credits:.6f}"
            )


        print()


    print("=" * 78)

    print(
        "RUN COMPLETE"
    )

    print("=" * 78)

    print(
        f"Credits this run — Direct: "
        f"{run_direct_credits:.6f}"
    )

    print(
        f"Credits this run — Canon: "
        f"{run_canon_credits:.6f}"
    )

    print(
        f"Credits this run — Total: "
        f"{run_direct_credits + run_canon_credits:.6f}"
    )

    print()

    print(
        f"Direct results:\n"
        f"{DIRECT_FILE}"
    )

    print()

    print(
        f"Canonicalized results:\n"
        f"{CANON_FILE}"
    )


if __name__ == "__main__":
    main()