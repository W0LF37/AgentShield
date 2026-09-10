import argparse
import json
import os
import time
from pathlib import Path

import requests

from canonicalizer import canonicalize


# ============================================================
# Project paths
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parent.parent

BENCHMARK_FILE = (
    PROJECT_ROOT
    / "dataset"
    / "generated"
    / "benchmark_v1.jsonl"
)

RESULTS_DIR = PROJECT_ROOT / "results"


# ============================================================
# Experiment metadata
# ============================================================

EXPERIMENT_NAME = "AgentShield-ObfusBench"

BENCHMARK_VERSION = "v1"

AGENT_VERSION = "v1_direct_classifier"

PROMPT_VERSION = "v1"

MODEL_NAME = "GPT-4o Mini"

PLATFORM = "aiXplain XStudio"

V1_PIPELINE = "v1_direct"

V2_PIPELINE = "v2_deterministic_canonicalization"

V2_PREPROCESSING = (
    "hex_base64_spaced_canonicalization"
)


# ============================================================
# aiXplain configuration
# ============================================================

API_KEY = os.getenv(
    "AIXPLAIN_API_KEY"
)

if not API_KEY:
    raise RuntimeError(
        "AIXPLAIN_API_KEY environment variable is not set."
    )


AGENT_ID = "6a9c1113731769e848571904"

RUN_URL = (
    f"https://platform-api.aixplain.com/"
    f"sdk/agents/{AGENT_ID}/run"
)

HEADERS = {
    "x-api-key": API_KEY,
    "Content-Type": "application/json",
}


# ============================================================
# Retry configuration
# ============================================================

MAX_ATTEMPTS = 3

BASE_RETRY_DELAY = 2

TRANSIENT_DIAGNOSTIC_CODES = {
    "MODEL_UNAVAILABLE",
    "SERVICE_UNAVAILABLE",
    "TIMEOUT",
    "RATE_LIMITED",
    "INTERNAL_SERVER_ERROR",
}


class TransientRunError(Exception):
    pass


# ============================================================
# JSONL helpers
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


def load_completed_ids(path):

    if not path.exists():
        return set()

    completed = set()

    for record in load_jsonl(
        path
    ):

        if (
            record.get("status")
            == "SUCCESS"
        ):

            completed.add(
                record["sample_id"]
            )

    return completed


# ============================================================
# Output normalization
# ============================================================

def normalize_output(output):

    normalized = dict(
        output
    )


    # --------------------------------------------------------
    # risk_score
    # --------------------------------------------------------

    try:

        normalized[
            "risk_score"
        ] = int(
            output.get(
                "risk_score",
                0
            )
        )

    except (
        TypeError,
        ValueError
    ):

        normalized[
            "risk_score"
        ] = None


    # --------------------------------------------------------
    # attack_types
    # --------------------------------------------------------

    attack_types = output.get(
        "attack_types",
        []
    )

    if isinstance(
        attack_types,
        str
    ):

        if (
            attack_types
            .strip()
            .lower()
            in {
                "",
                "none",
                "n/a",
            }
        ):

            attack_types = []

        else:

            attack_types = [
                item.strip()
                for item
                in attack_types.split(",")
                if item.strip()
            ]

    normalized[
        "attack_types"
    ] = attack_types


    # --------------------------------------------------------
    # suspicious_segments
    # --------------------------------------------------------

    suspicious_segments = (
        output.get(
            "suspicious_segments",
            []
        )
    )

    if isinstance(
        suspicious_segments,
        str
    ):

        if (
            suspicious_segments
            .strip()
            .lower()
            in {
                "",
                "none",
                "n/a",
            }
        ):

            suspicious_segments = []

        else:

            suspicious_segments = [
                suspicious_segments.strip()
            ]

    normalized[
        "suspicious_segments"
    ] = suspicious_segments


    return normalized


# ============================================================
# HTTP helpers
# ============================================================

def is_transient_http_status(
    status_code
):

    return (
        status_code == 408
        or status_code == 429
        or 500 <= status_code <= 599
    )


# ============================================================
# One API attempt
# ============================================================

def run_sample_once(
    input_text
):

    payload = {
        "query": input_text
    }


    response = requests.post(
        RUN_URL,
        headers=HEADERS,
        json=payload,
        timeout=30
    )


    if is_transient_http_status(
        response.status_code
    ):

        raise TransientRunError(
            f"Transient POST error: "
            f"HTTP {response.status_code}"
        )


    response.raise_for_status()

    run_data = response.json()


    request_id = run_data.get(
        "requestId"
    )

    result_url = run_data.get(
        "data"
    )


    if not result_url:

        raise RuntimeError(
            f"No result URL returned: "
            f"{run_data}"
        )


    print(
        f"        Request ID: "
        f"{request_id}"
    )


    # --------------------------------------------------------
    # Poll
    # --------------------------------------------------------

    for _ in range(60):

        response = requests.get(
            result_url,
            headers=HEADERS,
            timeout=30
        )


        if is_transient_http_status(
            response.status_code
        ):

            time.sleep(1)

            continue


        response.raise_for_status()

        result = response.json()


        if (
            result.get("completed")
            is True
        ):

            break


        time.sleep(1)


    else:

        raise TransientRunError(
            "Timed out while waiting "
            "for AgentShield."
        )


    # --------------------------------------------------------
    # Execution status
    # --------------------------------------------------------

    if (
        result.get("status")
        != "SUCCESS"
    ):

        data = result.get(
            "data",
            {}
        )

        diagnostic_codes = set(
            data.get(
                "diagnosticErrorCodes",
                []
            )
            or []
        )

        error_message = data.get(
            "error",
            "Unknown execution error."
        )


        if diagnostic_codes.intersection(
            TRANSIENT_DIAGNOSTIC_CODES
        ):

            raise TransientRunError(
                f"{sorted(diagnostic_codes)}: "
                f"{error_message}"
            )


        raise RuntimeError(
            f"Agent run failed: "
            f"{result}"
        )


    # --------------------------------------------------------
    # Parse classifier response
    # --------------------------------------------------------

    raw_output_text = (
        result[
            "data"
        ][
            "output"
        ]
    )


    try:

        raw_output = json.loads(
            raw_output_text
        )

    except json.JSONDecodeError:

        raw_output = {
            "_invalid_json":
                raw_output_text
        }


    normalized_output = (
        normalize_output(
            raw_output
        )
    )


    execution_stats = (
        result[
            "data"
        ].get(
            "executionStats",
            {}
        )
    )


    return {

        "request_id":
            request_id,

        "raw_output":
            raw_output,

        "normalized_output":
            normalized_output,

        "runtime_seconds":
            execution_stats.get(
                "runtime"
            ),

        "used_credits":
            execution_stats.get(
                "credits"
            ),

        "api_calls":
            execution_stats.get(
                "api_calls"
            ),
    }


# ============================================================
# Retry wrapper
# ============================================================

def run_sample(
    input_text
):

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

            result = run_sample_once(
                input_text
            )

            result[
                "attempts_used"
            ] = attempt

            result[
                "retry_errors"
            ] = retry_errors

            return result


        except TransientRunError as error:

            retry_errors.append(
                {
                    "attempt":
                        attempt,

                    "error":
                        str(error),
                }
            )


            print(
                f"        Temporary failure: "
                f"{error}"
            )


            if (
                attempt
                == MAX_ATTEMPTS
            ):

                raise RuntimeError(
                    "Maximum retry attempts "
                    "reached."
                )


            delay = (
                BASE_RETRY_DELAY
                * (
                    2
                    ** (
                        attempt - 1
                    )
                )
            )


            print(
                f"        Retrying in "
                f"{delay}s..."
            )

            time.sleep(
                delay
            )


# ============================================================
# Prepare V1 / V2 input
# ============================================================

def prepare_input(
    sample,
    pipeline
):

    original_text = sample[
        "text"
    ]


    # --------------------------------------------------------
    # V1:
    # send representation directly
    # --------------------------------------------------------

    if pipeline == "v1":

        return {

            "input_to_agent":
                original_text,

            "canonical_input":
                original_text,

            "detected_representation":
                "not_applied",

            "canonicalization_changed":
                False,

            "preprocessing":
                "none",

            "pipeline_version":
                V1_PIPELINE,
        }


    # --------------------------------------------------------
    # V2:
    # canonicalize first
    # --------------------------------------------------------

    canonicalization = canonicalize(
        original_text
    )


    return {

        "input_to_agent":
            canonicalization[
                "canonical_text"
            ],

        "canonical_input":
            canonicalization[
                "canonical_text"
            ],

        "detected_representation":
            canonicalization[
                "detected_representation"
            ],

        "canonicalization_changed":
            canonicalization[
                "changed"
            ],

        "preprocessing":
            V2_PREPROCESSING,

        "pipeline_version":
            V2_PIPELINE,
    }


# ============================================================
# Run one pipeline/sample
# ============================================================

def execute_sample(
    sample,
    pipeline,
    replicate,
    results_file
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

        run_result = run_sample(
            prepared[
                "input_to_agent"
            ]
        )


        record = {

            "experiment":
                EXPERIMENT_NAME,

            "benchmark_version":
                BENCHMARK_VERSION,

            "replicate":
                replicate,

            "pipeline":
                pipeline,

            "pipeline_version":
                prepared[
                    "pipeline_version"
                ],

            "agent_version":
                AGENT_VERSION,

            "prompt_version":
                PROMPT_VERSION,

            "model":
                MODEL_NAME,

            "platform":
                PLATFORM,

            "preprocessing":
                prepared[
                    "preprocessing"
                ],


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


            "original_input":
                sample[
                    "text"
                ],

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


            "status":
                "SUCCESS",

            **run_result,
        }


        append_jsonl(
            results_file,
            record
        )


        prediction = (
            run_result[
                "normalized_output"
            ].get(
                "classification"
            )
        )

        risk_score = (
            run_result[
                "normalized_output"
            ].get(
                "risk_score"
            )
        )


        print(
            f"        Truth: "
            f"{sample['label']}"
        )

        print(
            f"        Prediction: "
            f"{prediction}"
        )

        print(
            f"        Risk: "
            f"{risk_score}"
        )

        print(
            f"        Credits: "
            f"{run_result.get('used_credits')}"
        )


    except Exception as error:

        record = {

            "experiment":
                EXPERIMENT_NAME,

            "benchmark_version":
                BENCHMARK_VERSION,

            "replicate":
                replicate,

            "pipeline":
                pipeline,

            "pipeline_version":
                prepared[
                    "pipeline_version"
                ],

            "agent_version":
                AGENT_VERSION,

            "prompt_version":
                PROMPT_VERSION,

            "model":
                MODEL_NAME,

            "platform":
                PLATFORM,

            "preprocessing":
                prepared[
                    "preprocessing"
                ],

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

            "original_input":
                sample[
                    "text"
                ],

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

            "status":
                "ERROR",

            "error":
                str(error),
        }


        append_jsonl(
            results_file,
            record
        )


        print(
            f"        FINAL ERROR: "
            f"{error}"
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
            2,
            3
        ],
        help=(
            "Replication number. "
            "Use 2 or 3."
        )
    )

    args = parser.parse_args()

    replicate = args.replicate


    RESULTS_DIR.mkdir(
        parents=True,
        exist_ok=True
    )


    v1_results_file = (
        RESULTS_DIR
        / f"v1_rep{replicate}_results.jsonl"
    )

    v2_results_file = (
        RESULTS_DIR
        / f"v2_rep{replicate}_results.jsonl"
    )


    samples = load_jsonl(
        BENCHMARK_FILE
    )


    v1_completed = load_completed_ids(
        v1_results_file
    )

    v2_completed = load_completed_ids(
        v2_results_file
    )


    print(
        "=" * 72
    )

    print(
        f"AgentShield Replication "
        f"{replicate}"
    )

    print(
        "=" * 72
    )

    print(
        f"Samples: {len(samples)}"
    )

    print(
        f"V1 already complete: "
        f"{len(v1_completed)}"
    )

    print(
        f"V2 already complete: "
        f"{len(v2_completed)}"
    )

    print(
        "Order is interleaved "
        "to reduce temporal bias."
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
            f"[{index}/{len(samples)}] "
            f"{sample_id}"
        )


        # ----------------------------------------------------
        # Alternate pair order:
        #
        # odd sample:
        # V1 then V2
        #
        # even sample:
        # V2 then V1
        # ----------------------------------------------------

        if index % 2 == 1:

            pipeline_order = [
                "v1",
                "v2",
            ]

        else:

            pipeline_order = [
                "v2",
                "v1",
            ]


        for pipeline in pipeline_order:

            if pipeline == "v1":

                results_file = (
                    v1_results_file
                )

                completed = (
                    v1_completed
                )

            else:

                results_file = (
                    v2_results_file
                )

                completed = (
                    v2_completed
                )


            if sample_id in completed:

                print(
                    f"    {pipeline.upper()} "
                    f"SKIP — already SUCCESS"
                )

                continue


            execute_sample(
                sample,
                pipeline,
                replicate,
                results_file
            )


            time.sleep(
                0.5
            )


        print()


    print(
        "=" * 72
    )

    print(
        f"Replication {replicate} finished."
    )

    print(
        "=" * 72
    )

    print(
        "V1 results:"
    )

    print(
        v1_results_file
    )

    print()

    print(
        "V2 results:"
    )

    print(
        v2_results_file
    )


if __name__ == "__main__":
    main()