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

RESULTS_FILE = (
    RESULTS_DIR
    / "v2_official_results.jsonl"
)


# ============================================================
# Experiment metadata
# ============================================================

EXPERIMENT_NAME = "AgentShield-ObfusBench"

BENCHMARK_VERSION = "v1"

AGENT_VERSION = "v1_direct_classifier"

PROMPT_VERSION = "v1"

MODEL_NAME = "GPT-4o Mini"

PLATFORM = "aiXplain XStudio"

PIPELINE_VERSION = "v2_deterministic_canonicalization"

PREPROCESSING = (
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
    f"https://platform-api.aixplain.com/sdk/agents/"
    f"{AGENT_ID}/run"
)

HEADERS = {
    "x-api-key": API_KEY,
    "Content-Type": "application/json"
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

def load_jsonl(path: Path):

    with path.open(
        "r",
        encoding="utf-8"
    ) as file:

        for line in file:

            line = line.strip()

            if line:
                yield json.loads(
                    line
                )


def append_jsonl(
    path: Path,
    record: dict
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


# ============================================================
# Resume support
# ============================================================

def load_completed_ids():

    if not RESULTS_FILE.exists():
        return set()

    completed = set()

    for record in load_jsonl(
        RESULTS_FILE
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

def normalize_output(
    output: dict
):

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
                "n/a"
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
                "n/a"
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
    status_code: int
):

    return (
        status_code == 408
        or status_code == 429
        or 500 <= status_code <= 599
    )


# ============================================================
# Run one API attempt
# ============================================================

def run_sample_once(
    canonical_text: str
):

    payload = {
        "query": canonical_text
    }


    # --------------------------------------------------------
    # Start AgentShield
    # --------------------------------------------------------

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
    # Poll result
    # --------------------------------------------------------

    for _ in range(60):

        result_response = requests.get(
            result_url,
            headers=HEADERS,
            timeout=30
        )


        if is_transient_http_status(
            result_response.status_code
        ):

            time.sleep(1)

            continue


        result_response.raise_for_status()

        result = result_response.json()


        if (
            result.get("completed")
            is True
        ):

            break


        time.sleep(1)


    else:

        raise TransientRunError(
            "Timed out while waiting for "
            "AgentShield to complete."
        )


    # --------------------------------------------------------
    # Inspect status
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
            "Unknown agent execution error."
        )


        if (
            diagnostic_codes
            .intersection(
                TRANSIENT_DIAGNOSTIC_CODES
            )
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
    # Parse classifier output
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


    normalized_output = normalize_output(
        raw_output
    )


    # --------------------------------------------------------
    # Execution statistics
    # --------------------------------------------------------

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
            )
    }


# ============================================================
# Retry logic
# ============================================================

def run_sample(
    canonical_text: str
):

    retry_errors = []


    for attempt in range(
        1,
        MAX_ATTEMPTS + 1
    ):

        print(
            f"    Attempt "
            f"{attempt}/"
            f"{MAX_ATTEMPTS}"
        )


        try:

            result = run_sample_once(
                canonical_text
            )


            result[
                "attempts_used"
            ] = attempt

            result[
                "retry_errors"
            ] = retry_errors


            return result


        except TransientRunError as error:

            error_text = str(
                error
            )


            retry_errors.append(
                {
                    "attempt":
                        attempt,

                    "error":
                        error_text
                }
            )


            print(
                f"        Temporary failure: "
                f"{error_text}"
            )


            if (
                attempt
                == MAX_ATTEMPTS
            ):

                raise RuntimeError(
                    "Maximum retry attempts "
                    "reached after transient "
                    f"errors: {retry_errors}"
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
                f"{delay} seconds..."
            )


            time.sleep(
                delay
            )


# ============================================================
# Main V2 official benchmark
# ============================================================

def main():

    RESULTS_DIR.mkdir(
        parents=True,
        exist_ok=True
    )


    samples = list(
        load_jsonl(
            BENCHMARK_FILE
        )
    )


    completed_ids = (
        load_completed_ids()
    )


    print(
        f"Experiment: "
        f"{EXPERIMENT_NAME}"
    )

    print(
        f"Pipeline: "
        f"{PIPELINE_VERSION}"
    )

    print(
        f"Preprocessing: "
        f"{PREPROCESSING}"
    )

    print(
        f"Benchmark samples selected: "
        f"{len(samples)}"
    )

    print(
        f"Already completed successfully: "
        f"{len(completed_ids)}"
    )

    print()


    for index, sample in enumerate(
        samples,
        start=1
    ):

        sample_id = sample[
            "sample_id"
        ]


        if (
            sample_id
            in completed_ids
        ):

            print(
                f"[{index}/{len(samples)}] "
                f"SKIP {sample_id}"
            )

            continue


        # ====================================================
        # V2 DIFFERENCE:
        #
        # Canonicalize before sending the text to AgentShield.
        # ====================================================

        canonicalization = canonicalize(
            sample["text"]
        )


        canonical_text = (
            canonicalization[
                "canonical_text"
            ]
        )


        detected_representation = (
            canonicalization[
                "detected_representation"
            ]
        )


        canonicalization_changed = (
            canonicalization[
                "changed"
            ]
        )


        print(
            f"[{index}/{len(samples)}] "
            f"Running {sample_id}..."
        )

        print(
            f"    Dataset transformation: "
            f"{sample['transformation']}"
        )

        print(
            f"    Canonicalizer detected: "
            f"{detected_representation}"
        )

        print(
            f"    Canonicalized: "
            f"{canonicalization_changed}"
        )


        try:

            run_result = run_sample(
                canonical_text
            )


            record = {

                # --------------------------------------------
                # Experiment metadata
                # --------------------------------------------

                "experiment":
                    EXPERIMENT_NAME,

                "benchmark_version":
                    BENCHMARK_VERSION,

                "pipeline_version":
                    PIPELINE_VERSION,

                "agent_version":
                    AGENT_VERSION,

                "prompt_version":
                    PROMPT_VERSION,

                "model":
                    MODEL_NAME,

                "platform":
                    PLATFORM,

                "preprocessing":
                    PREPROCESSING,


                # --------------------------------------------
                # Sample metadata
                # --------------------------------------------

                "sample_id":
                    sample_id,

                "base_id":
                    sample["base_id"],

                "ground_truth":
                    sample["label"],

                "category":
                    sample["category"],

                "transformation":
                    sample[
                        "transformation"
                    ],


                # --------------------------------------------
                # Canonicalization metadata
                # --------------------------------------------

                "original_input":
                    sample["text"],

                "canonical_input":
                    canonical_text,

                "detected_representation":
                    detected_representation,

                "canonicalization_changed":
                    canonicalization_changed,


                # --------------------------------------------
                # Result
                # --------------------------------------------

                "status":
                    "SUCCESS",

                **run_result
            }


            append_jsonl(
                RESULTS_FILE,
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
                f"    Ground truth: "
                f"{sample['label']}"
            )

            print(
                f"    Prediction: "
                f"{prediction}"
            )

            print(
                f"    Risk score: "
                f"{risk_score}"
            )

            print(
                f"    Attempts used: "
                f"{run_result.get('attempts_used')}"
            )

            print(
                f"    Credits: "
                f"{run_result.get('used_credits')}"
            )

            print(
                f"    Runtime: "
                f"{run_result.get('runtime_seconds')}s"
            )


        except Exception as error:

            record = {

                "experiment":
                    EXPERIMENT_NAME,

                "benchmark_version":
                    BENCHMARK_VERSION,

                "pipeline_version":
                    PIPELINE_VERSION,

                "agent_version":
                    AGENT_VERSION,

                "prompt_version":
                    PROMPT_VERSION,

                "model":
                    MODEL_NAME,

                "platform":
                    PLATFORM,

                "preprocessing":
                    PREPROCESSING,

                "sample_id":
                    sample_id,

                "base_id":
                    sample["base_id"],

                "ground_truth":
                    sample["label"],

                "category":
                    sample["category"],

                "transformation":
                    sample[
                        "transformation"
                    ],

                "original_input":
                    sample["text"],

                "canonical_input":
                    canonical_text,

                "detected_representation":
                    detected_representation,

                "canonicalization_changed":
                    canonicalization_changed,

                "status":
                    "ERROR",

                "error":
                    str(error)
            }


            append_jsonl(
                RESULTS_FILE,
                record
            )


            print(
                f"    FINAL ERROR: "
                f"{error}"
            )


        time.sleep(
            0.5
        )


    print(
        "\nV2 official benchmark finished."
    )

    print(
        f"Results saved to:\n"
        f"{RESULTS_FILE}"
    )


if __name__ == "__main__":
    main()