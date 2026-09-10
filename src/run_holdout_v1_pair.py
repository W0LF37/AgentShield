import argparse
import hashlib
import json
import os
import time
from pathlib import Path

import requests

from canonicalizer import canonicalize


# ============================================================
# Paths
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parent.parent

BENCHMARK_FILE = (
    PROJECT_ROOT
    / "dataset"
    / "frozen_holdout_v1"
    / "holdout_benchmark_v1.jsonl"
)

RESULTS_DIR = (
    PROJECT_ROOT
    / "results"
)


# ============================================================
# aiXplain configuration
# ============================================================

API_KEY = os.getenv("AIXPLAIN_API_KEY")

if not API_KEY:
    raise RuntimeError(
        "AIXPLAIN_API_KEY environment variable is not set."
    )


AGENT_ID = "6a9c1113731769e848571904"

RUN_URL = (
    "https://platform-api.aixplain.com/"
    f"sdk/agents/{AGENT_ID}/run"
)

HEADERS = {
    "x-api-key": API_KEY,
    "Content-Type": "application/json",
}


# ============================================================
# Retry / polling
# ============================================================

MAX_ATTEMPTS = 3
POLL_INTERVAL_SECONDS = 1
MAX_POLL_ATTEMPTS = 90
BETWEEN_CALL_DELAY = 0.5

TRANSIENT_CODES = {
    "MODEL_UNAVAILABLE",
    "SERVICE_UNAVAILABLE",
    "TIMEOUT",
    "RATE_LIMITED",
    "INTERNAL_SERVER_ERROR",
}


class TransientRunError(Exception):
    pass


# ============================================================
# File helpers
# ============================================================

def sha256_file(path):

    digest = hashlib.sha256()

    with path.open("rb") as file:

        while True:

            chunk = file.read(
                1024 * 1024
            )

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


def append_jsonl(path, record):

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


def completed_ids(path):

    if not path.exists():
        return set()

    return {
        record["sample_id"]
        for record in load_jsonl(path)
        if record.get("status") == "SUCCESS"
    }


# ============================================================
# Output handling
# ============================================================

def normalize_output(output):

    if not isinstance(output, dict):
        return {
            "_invalid_output": output
        }


    result = dict(output)


    classification = result.get(
        "classification"
    )

    if isinstance(classification, str):

        classification = (
            classification
            .strip()
            .upper()
        )


    result["classification"] = (
        classification
    )


    risk = result.get(
        "risk_score"
    )

    try:

        result["risk_score"] = (
            int(float(risk))
            if risk is not None
            else None
        )

    except (
        TypeError,
        ValueError
    ):

        result["risk_score"] = None


    return result


# ============================================================
# API
# ============================================================

def transient_http(status_code):

    return (
        status_code == 408
        or status_code == 429
        or 500 <= status_code <= 599
    )


def run_once(text):

    response = requests.post(
        RUN_URL,
        headers=HEADERS,
        json={
            "query": text
        },
        timeout=30
    )


    if transient_http(
        response.status_code
    ):

        raise TransientRunError(
            f"POST HTTP "
            f"{response.status_code}"
        )


    response.raise_for_status()

    initial = response.json()


    request_id = initial.get(
        "requestId"
    )

    result_url = initial.get(
        "data"
    )


    if not result_url:

        raise RuntimeError(
            f"No result URL returned: "
            f"{initial}"
        )


    print(
        f"        Request ID: "
        f"{request_id}"
    )


    result = None


    for _ in range(
        MAX_POLL_ATTEMPTS
    ):

        response = requests.get(
            result_url,
            headers=HEADERS,
            timeout=30
        )


        if transient_http(
            response.status_code
        ):

            time.sleep(
                POLL_INTERVAL_SECONDS
            )

            continue


        response.raise_for_status()

        result = response.json()


        if result.get("completed") is True:
            break


        time.sleep(
            POLL_INTERVAL_SECONDS
        )


    else:

        raise TransientRunError(
            "Polling timeout."
        )


    if result.get("status") != "SUCCESS":

        data = result.get(
            "data",
            {}
        )

        if not isinstance(data, dict):
            data = {}


        codes = set(
            data.get(
                "diagnosticErrorCodes",
                []
            )
            or []
        )


        if codes.intersection(
            TRANSIENT_CODES
        ):

            raise TransientRunError(
                str(result)
            )


        raise RuntimeError(
            f"Agent failure: {result}"
        )


    data = result.get(
        "data",
        {}
    )


    output = data.get(
        "output"
    )


    if isinstance(output, str):

        try:

            raw_output = json.loads(
                output
            )

        except json.JSONDecodeError:

            raw_output = {
                "_invalid_json":
                    output
            }

    elif isinstance(output, dict):

        raw_output = output

    else:

        raw_output = {
            "_invalid_output":
                output
        }


    stats = data.get(
        "executionStats",
        {}
    )

    if not isinstance(stats, dict):
        stats = {}


    return {
        "request_id":
            request_id,

        "raw_output":
            raw_output,

        "normalized_output":
            normalize_output(
                raw_output
            ),

        "runtime_seconds":
            stats.get("runtime"),

        "used_credits":
            stats.get("credits"),

        "api_calls":
            stats.get("api_calls"),
    }


def run_with_retry(text):

    retry_errors = []


    for attempt in range(
        1,
        MAX_ATTEMPTS + 1
    ):

        print(
            f"        Attempt "
            f"{attempt}/{MAX_ATTEMPTS}"
        )


        try:

            result = run_once(text)

            result[
                "attempts_used"
            ] = attempt

            result[
                "retry_errors"
            ] = retry_errors

            return result


        except TransientRunError as error:

            retry_errors.append(
                str(error)
            )


            print(
                f"        Temporary error: "
                f"{error}"
            )


            if attempt == MAX_ATTEMPTS:

                raise RuntimeError(
                    "Maximum retry attempts reached."
                )


            delay = 2 ** attempt

            print(
                f"        Retrying in "
                f"{delay}s..."
            )

            time.sleep(delay)


# ============================================================
# Pipeline preparation
# ============================================================

def prepare_input(
    sample,
    pipeline
):

    text = sample["text"]


    if pipeline == "v1":

        return {
            "input_to_agent":
                text,

            "canonical_input":
                text,

            "detected_representation":
                "not_applied",

            "canonicalization_changed":
                False,

            "preprocessing":
                "none",
        }


    result = canonicalize(
        text
    )


    return {
        "input_to_agent":
            result.get(
                "canonical_text",
                text
            ),

        "canonical_input":
            result.get(
                "canonical_text",
                text
            ),

        "detected_representation":
            result.get(
                "detected_representation",
                "plain"
            ),

        "canonicalization_changed":
            bool(
                result.get(
                    "changed",
                    False
                )
            ),

        "preprocessing":
            "deterministic_canonicalization",
    }


# ============================================================
# Execute one pipeline
# ============================================================

def execute(
    sample,
    pipeline,
    replicate,
    output_file,
    benchmark_hash
):

    prepared = prepare_input(
        sample,
        pipeline
    )


    print(
        f"    {pipeline.upper()}"
    )

    print(
        f"        Transformation: "
        f"{sample['transformation']}"
    )

    print(
        f"        Canonicalized: "
        f"{prepared['canonicalization_changed']}"
    )


    try:

        result = run_with_retry(
            prepared[
                "input_to_agent"
            ]
        )


        record = {
            "experiment":
                "AgentShield-ObfusBench",

            "dataset":
                "synthetic_holdout_v1",

            "split":
                "holdout",

            "replicate":
                replicate,

            "pipeline":
                pipeline,

            "benchmark_sha256":
                benchmark_hash,

            "sample_id":
                sample["sample_id"],

            "base_id":
                sample["base_id"],

            "ground_truth":
                sample["label"],

            "category":
                sample["category"],

            "transformation":
                sample["transformation"],

            "source":
                sample.get("source"),

            "original_base_text":
                sample["original_text"],

            "original_input":
                sample["text"],

            "canonical_input":
                prepared[
                    "canonical_input"
                ],

            "input_to_agent":
                prepared[
                    "input_to_agent"
                ],

            "detected_representation":
                prepared[
                    "detected_representation"
                ],

            "canonicalization_changed":
                prepared[
                    "canonicalization_changed"
                ],

            "preprocessing":
                prepared[
                    "preprocessing"
                ],

            "status":
                "SUCCESS",

            **result,
        }


        append_jsonl(
            output_file,
            record
        )


        pred = (
            result[
                "normalized_output"
            ].get(
                "classification"
            )
        )


        print(
            f"        Truth: "
            f"{sample['label']}"
        )

        print(
            f"        Prediction: "
            f"{pred}"
        )

        print(
            f"        Credits: "
            f"{result.get('used_credits')}"
        )


        return True


    except Exception as error:

        append_jsonl(
            output_file,
            {
                "experiment":
                    "AgentShield-ObfusBench",

                "dataset":
                    "synthetic_holdout_v1",

                "split":
                    "holdout",

                "replicate":
                    replicate,

                "pipeline":
                    pipeline,

                "benchmark_sha256":
                    benchmark_hash,

                "sample_id":
                    sample[
                        "sample_id"
                    ],

                "base_id":
                    sample[
                        "base_id"
                    ],

                "ground_truth":
                    sample[
                        "label"
                    ],

                "category":
                    sample[
                        "category"
                    ],

                "transformation":
                    sample[
                        "transformation"
                    ],

                "status":
                    "ERROR",

                "error":
                    str(error),
            }
        )


        print(
            f"        ERROR: {error}"
        )


        return False


# ============================================================
# Main
# ============================================================

def main():

    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--replicate",
        type=int,
        required=True,
        choices=[
            1,
            2,
            3
        ]
    )

    args = parser.parse_args()

    replicate = args.replicate


    if not BENCHMARK_FILE.exists():

        raise FileNotFoundError(
            f"Frozen holdout benchmark "
            f"not found:\n"
            f"{BENCHMARK_FILE}"
        )


    benchmark_hash = sha256_file(
        BENCHMARK_FILE
    )


    samples = load_jsonl(
        BENCHMARK_FILE
    )


    if len(samples) != 1000:

        raise RuntimeError(
            f"Expected 1000 holdout samples, "
            f"found {len(samples)}."
        )


    if len({
        sample["sample_id"]
        for sample in samples
    }) != 1000:

        raise RuntimeError(
            "Duplicate sample IDs detected."
        )


    if len({
        sample["base_id"]
        for sample in samples
    }) != 200:

        raise RuntimeError(
            "Expected 200 unique base IDs."
        )


    RESULTS_DIR.mkdir(
        parents=True,
        exist_ok=True
    )


    v1_file = (
        RESULTS_DIR
        / (
            f"holdout_v1_v1_rep"
            f"{replicate}_results.jsonl"
        )
    )


    v2_file = (
        RESULTS_DIR
        / (
            f"holdout_v1_v2_rep"
            f"{replicate}_results.jsonl"
        )
    )


    v1_completed = completed_ids(
        v1_file
    )

    v2_completed = completed_ids(
        v2_file
    )


    print("=" * 78)

    print(
        "AgentShield-ObfusBench"
    )

    print(
        "Synthetic Holdout v1 — V1 vs V2"
    )

    print("=" * 78)

    print(
        f"Replicate: {replicate}"
    )

    print(
        f"Samples: {len(samples)}"
    )

    print(
        f"V1 already SUCCESS: "
        f"{len(v1_completed)}"
    )

    print(
        f"V2 already SUCCESS: "
        f"{len(v2_completed)}"
    )

    print()

    print(
        "Benchmark SHA256:"
    )

    print(
        benchmark_hash
    )

    print()


    for index, sample in enumerate(
        samples,
        start=1
    ):

        sample_id = (
            sample[
                "sample_id"
            ]
        )


        print(
            f"[{index}/1000] "
            f"{sample_id}"
        )


        # Alternate order to reduce timing bias
        if index % 2 == 1:

            order = [
                "v1",
                "v2"
            ]

        else:

            order = [
                "v2",
                "v1"
            ]


        for pipeline in order:

            if pipeline == "v1":

                output_file = v1_file
                completed = v1_completed

            else:

                output_file = v2_file
                completed = v2_completed


            if sample_id in completed:

                print(
                    f"    {pipeline.upper()} "
                    f"SKIP — already SUCCESS"
                )

                continue


            success = execute(
                sample=sample,
                pipeline=pipeline,
                replicate=replicate,
                output_file=output_file,
                benchmark_hash=benchmark_hash,
            )


            if success:

                completed.add(
                    sample_id
                )


            time.sleep(
                BETWEEN_CALL_DELAY
            )


        print()


    print("=" * 78)

    print(
        f"Replicate {replicate} finished"
    )

    print("=" * 78)

    print(
        f"V1 Unique SUCCESS: "
        f"{len(v1_completed)}"
    )

    print(
        f"V2 Unique SUCCESS: "
        f"{len(v2_completed)}"
    )

    print()

    print(
        "V1 file:"
    )

    print(
        v1_file
    )

    print()

    print(
        "V2 file:"
    )

    print(
        v2_file
    )


if __name__ == "__main__":
    main()