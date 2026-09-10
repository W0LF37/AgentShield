import argparse
import hashlib
import json
import os
import time
from pathlib import Path

import requests

from typoglycemia_normalizer import normalize_typoglycemia


# ============================================================
# Paths
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parent.parent

BENCHMARK_FILE = (
    PROJECT_ROOT
    / "dataset"
    / "frozen_v2"
    / "benchmark_v2.jsonl"
)

NORMALIZER_FILE = (
    Path(__file__).resolve().parent
    / "typoglycemia_normalizer.py"
)

RESULTS_DIR = (
    PROJECT_ROOT
    / "results"
)


# ============================================================
# aiXplain
# ============================================================

API_KEY = os.getenv(
    "AIXPLAIN_API_KEY"
)

if not API_KEY:
    raise RuntimeError(
        "AIXPLAIN_API_KEY is not set."
    )


AGENT_ID = (
    "6a9c1113731769e848571904"
)

RUN_URL = (
    "https://platform-api.aixplain.com/"
    f"sdk/agents/{AGENT_ID}/run"
)

HEADERS = {
    "x-api-key": API_KEY,
    "Content-Type": "application/json",
}


# ============================================================
# Configuration
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
# Helpers
# ============================================================

def sha256_file(path):

    digest = hashlib.sha256()

    with path.open(
        "rb"
    ) as file:

        while True:

            chunk = file.read(
                1024 * 1024
            )

            if not chunk:
                break

            digest.update(
                chunk
            )

    return digest.hexdigest()


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


def append_jsonl(
    path,
    record
):

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


def normalize_output(output):

    if not isinstance(
        output,
        dict
    ):

        return {
            "_invalid_output": output
        }


    result = dict(
        output
    )


    classification = result.get(
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


    result[
        "classification"
    ] = classification


    risk = result.get(
        "risk_score"
    )

    try:

        result[
            "risk_score"
        ] = (
            int(float(risk))
            if risk is not None
            else None
        )

    except (
        TypeError,
        ValueError
    ):

        result[
            "risk_score"
        ] = None


    return result


# ============================================================
# API
# ============================================================

def transient_http(code):

    return (
        code == 408
        or code == 429
        or 500 <= code <= 599
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
            f"No result URL: {initial}"
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


        if result.get(
            "completed"
        ) is True:

            break


        time.sleep(
            POLL_INTERVAL_SECONDS
        )


    else:

        raise TransientRunError(
            "Polling timeout."
        )


    if result.get(
        "status"
    ) != "SUCCESS":

        data = result.get(
            "data",
            {}
        )

        if not isinstance(
            data,
            dict
        ):
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


    if isinstance(
        output,
        str
    ):

        try:

            raw_output = json.loads(
                output
            )

        except json.JSONDecodeError:

            raw_output = {
                "_invalid_json":
                    output
            }

    elif isinstance(
        output,
        dict
    ):

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

    if not isinstance(
        stats,
        dict
    ):
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
            stats.get(
                "runtime"
            ),

        "used_credits":
            stats.get(
                "credits"
            ),

        "api_calls":
            stats.get(
                "api_calls"
            ),
    }


def run_with_retry(text):

    errors = []


    for attempt in range(
        1,
        MAX_ATTEMPTS + 1
    ):

        print(
            f"        Attempt "
            f"{attempt}/{MAX_ATTEMPTS}"
        )


        try:

            result = run_once(
                text
            )

            result[
                "attempts_used"
            ] = attempt

            result[
                "retry_errors"
            ] = errors

            return result


        except TransientRunError as error:

            errors.append(
                str(error)
            )


            if attempt == MAX_ATTEMPTS:

                raise RuntimeError(
                    "Maximum retry attempts reached."
                )


            delay = (
                2
                ** attempt
            )


            print(
                f"        Temporary error. "
                f"Retrying in {delay}s..."
            )

            time.sleep(
                delay
            )


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


    benchmark_hash = sha256_file(
        BENCHMARK_FILE
    )

    normalizer_hash = sha256_file(
        NORMALIZER_FILE
    )


    all_samples = load_jsonl(
        BENCHMARK_FILE
    )


    samples = [
        sample
        for sample in all_samples
        if (
            sample[
                "transformation"
            ]
            == "typoglycemia"
        )
    ]


    if len(samples) != 100:

        raise RuntimeError(
            f"Expected 100 typoglycemia "
            f"samples, found {len(samples)}."
        )


    RESULTS_DIR.mkdir(
        parents=True,
        exist_ok=True
    )


    output_file = (
        RESULTS_DIR
        / (
            "benchmark_v2_"
            f"v3_typoglycemia_rep"
            f"{replicate}_results.jsonl"
        )
    )


    completed = completed_ids(
        output_file
    )


    print(
        "=" * 78
    )

    print(
        "AgentShield-ObfusBench"
    )

    print(
        "V3 Typoglycemia Normalization"
    )

    print(
        "=" * 78
    )

    print(
        f"Replicate: {replicate}"
    )

    print(
        f"Samples: {len(samples)}"
    )

    print(
        f"Already completed: "
        f"{len(completed)}"
    )

    print(
        f"Benchmark SHA256:"
    )

    print(
        benchmark_hash
    )

    print(
        f"Normalizer SHA256:"
    )

    print(
        normalizer_hash
    )

    print()


    for index, sample in enumerate(
        samples,
        start=1
    ):

        sample_id = sample[
            "sample_id"
        ]


        print(
            f"[{index}/100] "
            f"{sample_id}"
        )


        if sample_id in completed:

            print(
                "    SKIP — already SUCCESS"
            )

            continue


        normalization = (
            normalize_typoglycemia(
                sample[
                    "text"
                ]
            )
        )


        normalized_text = (
            normalization[
                "canonical_text"
            ]
        )


        exact_recovery = (
            normalized_text
            == sample[
                "original_text"
            ]
        )


        print(
            f"    Replacements: "
            f"{normalization['replacement_count']}"
        )

        print(
            f"    Exact recovery: "
            f"{exact_recovery}"
        )


        try:

            result = run_with_retry(
                normalized_text
            )


            pred = result[
                "normalized_output"
            ].get(
                "classification"
            )


            record = {
                "experiment":
                    "AgentShield-ObfusBench",

                "benchmark_version":
                    "v2",

                "pipeline":
                    "v3_typoglycemia",

                "replicate":
                    replicate,

                "benchmark_sha256":
                    benchmark_hash,

                "normalizer_sha256":
                    normalizer_hash,

                "sample_id":
                    sample_id,

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
                    "typoglycemia",

                "source":
                    sample.get(
                        "source"
                    ),

                "original_base_text":
                    sample[
                        "original_text"
                    ],

                "transformed_input":
                    sample[
                        "text"
                    ],

                "normalized_input":
                    normalized_text,

                "normalization_changed":
                    normalization[
                        "changed"
                    ],

                "replacement_count":
                    normalization[
                        "replacement_count"
                    ],

                "replacements":
                    normalization[
                        "replacements"
                    ],

                "exact_text_recovery":
                    exact_recovery,

                "normalization_method":
                    normalization[
                        "method"
                    ],

                "status":
                    "SUCCESS",

                **result,
            }


            append_jsonl(
                output_file,
                record
            )


            completed.add(
                sample_id
            )


            print(
                f"    Truth: "
                f"{sample['label']}"
            )

            print(
                f"    Prediction: "
                f"{pred}"
            )

            print(
                f"    Credits: "
                f"{result.get('used_credits')}"
            )


        except Exception as error:

            append_jsonl(
                output_file,
                {
                    "sample_id":
                        sample_id,

                    "replicate":
                        replicate,

                    "pipeline":
                        "v3_typoglycemia",

                    "status":
                        "ERROR",

                    "error":
                        str(error),
                }
            )


            print(
                f"    ERROR: {error}"
            )


        time.sleep(
            BETWEEN_CALL_DELAY
        )

        print()


    records = load_jsonl(
        output_file
    )


    success_ids = {
        r.get(
            "sample_id"
        )
        for r in records
        if r.get(
            "status"
        ) == "SUCCESS"
    }


    error_count = sum(
        1
        for r in records
        if r.get(
            "status"
        ) == "ERROR"
    )


    print(
        "=" * 78
    )

    print(
        f"Replicate {replicate} finished"
    )

    print(
        "=" * 78
    )

    print(
        f"Unique SUCCESS: "
        f"{len(success_ids)}"
    )

    print(
        f"ERROR records: "
        f"{error_count}"
    )

    print(
        f"Saved to:"
    )

    print(
        output_file
    )


if __name__ == "__main__":
    main()