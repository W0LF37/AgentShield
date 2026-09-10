import argparse
import hashlib
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
    / "frozen_v2"
    / "benchmark_v2.jsonl"
)

RESULTS_DIR = (
    PROJECT_ROOT
    / "results"
)


# ============================================================
# Experiment metadata
# ============================================================

EXPERIMENT_NAME = "AgentShield-ObfusBench"

BENCHMARK_VERSION = "v2"

AGENT_VERSION = "v1_direct_classifier"

PROMPT_VERSION = "v1"

MODEL_NAME = "GPT-4o Mini"

PLATFORM = "aiXplain XStudio"

V1_PIPELINE_VERSION = "v1_direct_classifier"

V2_PIPELINE_VERSION = (
    "v2_deterministic_canonicalization"
)

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
        "AIXPLAIN_API_KEY environment variable "
        "is not set."
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
# Retry configuration
# ============================================================

MAX_ATTEMPTS = 3

BASE_RETRY_DELAY = 2

POLL_INTERVAL_SECONDS = 1

MAX_POLL_ATTEMPTS = 90

BETWEEN_CALL_DELAY = 0.5


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
# File helpers
# ============================================================

def calculate_sha256(path):

    sha256 = hashlib.sha256()

    with path.open(
        "rb"
    ) as file:

        while True:

            chunk = file.read(
                1024 * 1024
            )

            if not chunk:
                break

            sha256.update(
                chunk
            )

    return sha256.hexdigest()


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
                    f"Invalid JSON in "
                    f"{path.name} "
                    f"at line "
                    f"{line_number}: "
                    f"{error}"
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
                record.get(
                    "sample_id"
                )
            )

    return completed


# ============================================================
# Output normalization
# ============================================================

def normalize_output(output):

    if not isinstance(
        output,
        dict
    ):

        return {
            "_invalid_output":
                output
        }


    normalized = dict(
        output
    )


    # --------------------------------------------------------
    # Classification
    # --------------------------------------------------------

    classification = output.get(
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

    normalized[
        "classification"
    ] = classification


    # --------------------------------------------------------
    # Risk score
    # --------------------------------------------------------

    risk_score = output.get(
        "risk_score"
    )

    try:

        if risk_score is None:
            normalized[
                "risk_score"
            ] = None

        else:
            normalized[
                "risk_score"
            ] = int(
                float(
                    risk_score
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

        stripped = (
            attack_types
            .strip()
        )

        if stripped.lower() in {
            "",
            "none",
            "n/a",
            "null",
        }:

            attack_types = []

        else:

            attack_types = [
                item.strip()
                for item
                in stripped.split(",")
                if item.strip()
            ]


    if attack_types is None:
        attack_types = []


    normalized[
        "attack_types"
    ] = attack_types


    # --------------------------------------------------------
    # suspicious_segments
    # --------------------------------------------------------

    suspicious_segments = output.get(
        "suspicious_segments",
        []
    )

    if isinstance(
        suspicious_segments,
        str
    ):

        stripped = (
            suspicious_segments
            .strip()
        )

        if stripped.lower() in {
            "",
            "none",
            "n/a",
            "null",
        }:

            suspicious_segments = []

        else:

            suspicious_segments = [
                stripped
            ]


    if suspicious_segments is None:
        suspicious_segments = []


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
            "Transient POST error: "
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
            "No result URL returned. "
            f"Response: {run_data}"
        )


    print(
        f"        Request ID: "
        f"{request_id}"
    )


    # --------------------------------------------------------
    # Poll result URL
    # --------------------------------------------------------

    result = None


    for _ in range(
        MAX_POLL_ATTEMPTS
    ):

        response = requests.get(
            result_url,
            headers=HEADERS,
            timeout=30
        )


        if is_transient_http_status(
            response.status_code
        ):

            time.sleep(
                POLL_INTERVAL_SECONDS
            )

            continue


        response.raise_for_status()

        result = response.json()


        if (
            result.get("completed")
            is True
        ):

            break


        time.sleep(
            POLL_INTERVAL_SECONDS
        )


    else:

        raise TransientRunError(
            "Timed out while waiting "
            "for AgentShield result."
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

        if not isinstance(
            data,
            dict
        ):

            data = {}


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
            "Agent run failed: "
            f"{result}"
        )


    # --------------------------------------------------------
    # Output parsing
    # --------------------------------------------------------

    data = result.get(
        "data",
        {}
    )


    raw_output_text = data.get(
        "output"
    )


    if isinstance(
        raw_output_text,
        dict
    ):

        raw_output = (
            raw_output_text
        )

    elif isinstance(
        raw_output_text,
        str
    ):

        try:

            raw_output = json.loads(
                raw_output_text
            )

        except json.JSONDecodeError:

            raw_output = {
                "_invalid_json":
                    raw_output_text
            }

    else:

        raw_output = {
            "_invalid_output":
                raw_output_text
        }


    normalized_output = (
        normalize_output(
            raw_output
        )
    )


    # --------------------------------------------------------
    # Execution statistics
    # --------------------------------------------------------

    execution_stats = data.get(
        "executionStats",
        {}
    )

    if not isinstance(
        execution_stats,
        dict
    ):

        execution_stats = {}


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

            retry_errors.append({
                "attempt":
                    attempt,

                "error":
                    str(error),
            })


            print(
                "        Temporary failure: "
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
# Canonicalization compatibility helper
# ============================================================

def prepare_v2_input(
    original_text
):

    result = canonicalize(
        original_text
    )


    canonical_text = result.get(
        "canonical_text",
        original_text
    )


    detected_representation = (
        result.get(
            "detected_representation",
            "plain"
        )
    )


    changed = result.get(
        "changed",
        canonical_text != original_text
    )


    return {
        "input_to_agent":
            canonical_text,

        "canonical_input":
            canonical_text,

        "detected_representation":
            detected_representation,

        "canonicalization_changed":
            bool(changed),
    }


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
    # V1 = direct classifier
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
                V1_PIPELINE_VERSION,
        }


    # --------------------------------------------------------
    # V2 = canonicalize then same classifier
    # --------------------------------------------------------

    prepared = prepare_v2_input(
        original_text
    )


    prepared[
        "preprocessing"
    ] = V2_PREPROCESSING

    prepared[
        "pipeline_version"
    ] = V2_PIPELINE_VERSION


    return prepared


# ============================================================
# Run one sample / pipeline
# ============================================================

def execute_sample(
    sample,
    pipeline,
    replicate,
    results_file,
    benchmark_sha256
):

    prepared = prepare_input(
        sample,
        pipeline
    )


    print(
        f"    {pipeline.upper()}"
    )

    print(
        "        Transformation: "
        f"{sample['transformation']}"
    )

    print(
        "        Canonicalized: "
        f"{prepared['canonicalization_changed']}"
    )


    try:

        run_result = run_sample(
            prepared[
                "input_to_agent"
            ]
        )


        record = {
            # ------------------------------------------------
            # Experiment metadata
            # ------------------------------------------------

            "experiment":
                EXPERIMENT_NAME,

            "benchmark_version":
                BENCHMARK_VERSION,

            "benchmark_sha256":
                benchmark_sha256,

            "benchmark_file":
                str(
                    BENCHMARK_FILE
                    .relative_to(
                        PROJECT_ROOT
                    )
                ),

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


            # ------------------------------------------------
            # Dataset metadata
            # ------------------------------------------------

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

            "source":
                sample.get(
                    "source"
                ),


            # ------------------------------------------------
            # Input trace
            # ------------------------------------------------

            "original_base_text":
                sample.get(
                    "original_text"
                ),

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


            # ------------------------------------------------
            # Run result
            # ------------------------------------------------

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
            "        Truth: "
            f"{sample['label']}"
        )

        print(
            "        Prediction: "
            f"{prediction}"
        )

        print(
            "        Risk: "
            f"{risk_score}"
        )

        print(
            "        Credits: "
            f"{run_result.get('used_credits')}"
        )


        return True


    except Exception as error:

        record = {
            "experiment":
                EXPERIMENT_NAME,

            "benchmark_version":
                BENCHMARK_VERSION,

            "benchmark_sha256":
                benchmark_sha256,

            "benchmark_file":
                str(
                    BENCHMARK_FILE
                    .relative_to(
                        PROJECT_ROOT
                    )
                ),

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

            "source":
                sample.get(
                    "source"
                ),

            "original_base_text":
                sample.get(
                    "original_text"
                ),

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
            "        FINAL ERROR: "
            f"{error}"
        )


        return False


# ============================================================
# Validation
# ============================================================

def validate_benchmark(
    samples
):

    if len(samples) != 500:

        raise RuntimeError(
            "Frozen benchmark must contain "
            f"500 samples, found "
            f"{len(samples)}."
        )


    sample_ids = [
        sample.get(
            "sample_id"
        )
        for sample in samples
    ]


    if (
        len(sample_ids)
        != len(
            set(sample_ids)
        )
    ):

        raise RuntimeError(
            "Duplicate sample IDs detected "
            "in frozen benchmark."
        )


    base_ids = {
        sample.get(
            "base_id"
        )
        for sample in samples
    }


    if len(base_ids) != 100:

        raise RuntimeError(
            "Frozen benchmark must contain "
            f"100 base IDs, found "
            f"{len(base_ids)}."
        )


# ============================================================
# Summary helper
# ============================================================

def summarize_result_file(
    path
):

    if not path.exists():

        return {
            "total_records": 0,
            "success": 0,
            "errors": 0,
            "unique_success": 0,
        }


    records = load_jsonl(
        path
    )


    success_records = [
        record
        for record in records
        if (
            record.get("status")
            == "SUCCESS"
        )
    ]


    error_records = [
        record
        for record in records
        if (
            record.get("status")
            == "ERROR"
        )
    ]


    unique_success = {
        record.get(
            "sample_id"
        )
        for record in success_records
    }


    return {
        "total_records":
            len(records),

        "success":
            len(success_records),

        "errors":
            len(error_records),

        "unique_success":
            len(unique_success),
    }


# ============================================================
# Main
# ============================================================

def main():

    parser = argparse.ArgumentParser(
        description=(
            "Run frozen Benchmark v2 "
            "against V1 direct and "
            "V2 canonicalized pipelines."
        )
    )


    parser.add_argument(
        "--replicate",
        type=int,
        required=True,
        choices=[
            1,
            2,
            3
        ],
        help=(
            "Replicate number: 1, 2, or 3."
        )
    )


    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help=(
            "Run only the first N benchmark "
            "samples. Useful for sanity testing. "
            "Later rerunning without --limit "
            "will resume automatically."
        )
    )


    args = parser.parse_args()


    replicate = (
        args.replicate
    )

    limit = (
        args.limit
    )


    # --------------------------------------------------------
    # Frozen benchmark checks
    # --------------------------------------------------------

    if not BENCHMARK_FILE.exists():

        raise FileNotFoundError(
            "Frozen benchmark not found:\n"
            f"{BENCHMARK_FILE}"
        )


    benchmark_sha256 = (
        calculate_sha256(
            BENCHMARK_FILE
        )
    )


    samples = load_jsonl(
        BENCHMARK_FILE
    )


    validate_benchmark(
        samples
    )


    # --------------------------------------------------------
    # Apply optional sanity limit
    # --------------------------------------------------------

    selected_samples = samples


    if limit is not None:

        if (
            limit < 1
            or limit > len(samples)
        ):

            raise ValueError(
                "--limit must be between "
                f"1 and {len(samples)}."
            )


        selected_samples = (
            samples[
                :limit
            ]
        )


    # --------------------------------------------------------
    # Result paths
    # --------------------------------------------------------

    RESULTS_DIR.mkdir(
        parents=True,
        exist_ok=True
    )


    v1_results_file = (
        RESULTS_DIR
        / (
            "benchmark_v2_"
            f"v1_rep{replicate}_"
            "results.jsonl"
        )
    )


    v2_results_file = (
        RESULTS_DIR
        / (
            "benchmark_v2_"
            f"v2_rep{replicate}_"
            "results.jsonl"
        )
    )


    # --------------------------------------------------------
    # Resume state
    # --------------------------------------------------------

    v1_completed = load_completed_ids(
        v1_results_file
    )

    v2_completed = load_completed_ids(
        v2_results_file
    )


    print(
        "=" * 78
    )

    print(
        "AgentShield-ObfusBench "
        "Final Benchmark v2"
    )

    print(
        "=" * 78
    )

    print(
        f"Replicate: "
        f"{replicate}"
    )

    print(
        f"Frozen benchmark: "
        f"{BENCHMARK_FILE}"
    )

    print(
        f"SHA256: "
        f"{benchmark_sha256}"
    )

    print(
        f"Full benchmark samples: "
        f"{len(samples)}"
    )

    print(
        f"Selected this run: "
        f"{len(selected_samples)}"
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
        "Execution order: interleaved V1/V2"
    )

    print()


    # ========================================================
    # Main benchmark loop
    # ========================================================

    for index, sample in enumerate(
        selected_samples,
        start=1
    ):

        sample_id = (
            sample[
                "sample_id"
            ]
        )


        print(
            f"[{index}/{len(selected_samples)}] "
            f"{sample_id}"
        )


        # ----------------------------------------------------
        # Alternate order to reduce temporal ordering bias.
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


            # ------------------------------------------------
            # Resume: do not repeat successful sample.
            # ------------------------------------------------

            if sample_id in completed:

                print(
                    f"    {pipeline.upper()} "
                    "SKIP — already SUCCESS"
                )

                continue


            success = execute_sample(
                sample=sample,
                pipeline=pipeline,
                replicate=replicate,
                results_file=results_file,
                benchmark_sha256=benchmark_sha256,
            )


            if success:

                completed.add(
                    sample_id
                )


            time.sleep(
                BETWEEN_CALL_DELAY
            )


        print()


    # ========================================================
    # Final run summary
    # ========================================================

    v1_summary = summarize_result_file(
        v1_results_file
    )

    v2_summary = summarize_result_file(
        v2_results_file
    )


    print(
        "=" * 78
    )

    print(
        f"Replicate {replicate} run finished."
    )

    print(
        "=" * 78
    )

    print()

    print(
        "V1 results:"
    )

    print(
        v1_results_file
    )

    print(
        f"  SUCCESS: "
        f"{v1_summary['success']}"
    )

    print(
        f"  ERROR records: "
        f"{v1_summary['errors']}"
    )

    print(
        f"  Unique SUCCESS: "
        f"{v1_summary['unique_success']}"
    )

    print()

    print(
        "V2 results:"
    )

    print(
        v2_results_file
    )

    print(
        f"  SUCCESS: "
        f"{v2_summary['success']}"
    )

    print(
        f"  ERROR records: "
        f"{v2_summary['errors']}"
    )

    print(
        f"  Unique SUCCESS: "
        f"{v2_summary['unique_success']}"
    )

    print()

    print(
        "Benchmark SHA256:"
    )

    print(
        benchmark_sha256
    )


if __name__ == "__main__":
    main()