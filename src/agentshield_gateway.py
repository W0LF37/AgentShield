import os
import re
import json
import time
import uuid
import base64
import hashlib
import argparse
from pathlib import Path
from datetime import datetime, timezone

import requests

import redteam_canonicalizer_v4 as canonicalizer_v4


# ============================================================
# Configuration
# ============================================================

CLASSIFIER_AGENT_ID = "6a9c1113731769e848571904"

PROJECT_ROOT = Path(__file__).resolve().parent.parent
RESULTS_DIR = PROJECT_ROOT / "results"

AUDIT_LOG_FILE = (
    RESULTS_DIR
    / "agentshield_gateway_audit.jsonl"
)

AIXPLAIN_RUN_URL = (
    "https://platform-api.aixplain.com"
    f"/v2/agents/{CLASSIFIER_AGENT_ID}/run"
)

SECURITY_LEVEL = {
    "SAFE": 0,
    "SUSPICIOUS": 1,
    "MALICIOUS": 2,
}

POLICY_ACTION = {
    "SAFE": "ALLOW",
    "SUSPICIOUS": "REVIEW",
    "MALICIOUS": "BLOCK",
}

SUPPORTED_REPRESENTATIONS = {
    "auto",
    "plain",
    "hex",
    "base64",
    "spaced",
    "url_percent",
    "unicode_escape",
    "html_entities",
    "rot13",
    "typoglycemia",
}


# ============================================================
# Representation detection
# ============================================================

HEX_PATTERN = re.compile(
    r"^(?:[0-9A-Fa-f]{2})(?: [0-9A-Fa-f]{2})+$"
)

BASE64_PATTERN = re.compile(
    r"^[A-Za-z0-9+/]+={0,2}$"
)

UNICODE_ESCAPE_PATTERN = re.compile(
    r"(?:\\u[0-9A-Fa-f]{4}|\\U[0-9A-Fa-f]{8})"
)

HTML_ENTITY_PATTERN = re.compile(
    r"^(?:(?:&#\d+;)|(?:&#x[0-9A-Fa-f]+;))+$"
)

URL_PERCENT_PATTERN = re.compile(
    r"%[0-9A-Fa-f]{2}"
)


# ============================================================
# Utility
# ============================================================

def now_iso():
    return datetime.now(
        timezone.utc
    ).isoformat()


def sha256_text(text):
    return hashlib.sha256(
        text.encode("utf-8")
    ).hexdigest()


def append_jsonl(path, record):
    path.parent.mkdir(
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


def is_printable_text(text):
    if not text:
        return False

    return all(
        char.isprintable()
        or char in "\n\r\t"
        for char in text
    )


# ============================================================
# Auto-detection
# ============================================================

def looks_like_base64(text):
    if len(text) < 16:
        return False

    if len(text) % 4 != 0:
        return False

    if not BASE64_PATTERN.fullmatch(text):
        return False

    try:
        decoded = base64.b64decode(
            text,
            validate=True
        ).decode("utf-8")

        return is_printable_text(
            decoded
        )

    except Exception:
        return False


def looks_like_spaced(text):
    if len(text) < 5:
        return False

    # Example:
    # H e l l o
    #
    # Odd positions must all be spaces.
    return all(
        text[index] == " "
        for index in range(
            1,
            len(text),
            2
        )
    )


def detect_representation(text):

    # Unicode escape:
    # \u0048\u0065...
    unicode_hits = (
        text.count("\\u")
        + text.count("\\U")
    )

    if (
        unicode_hits >= 2
        and UNICODE_ESCAPE_PATTERN.search(text)
    ):
        return "unicode_escape"


    # Numeric HTML entities:
    # &#72;&#101;...
    if HTML_ENTITY_PATTERN.fullmatch(
        text
    ):
        return "html_entities"


    # Space-separated hex bytes.
    if HEX_PATTERN.fullmatch(
        text
    ):
        return "hex"


    # Strict valid Base64.
    if looks_like_base64(
        text
    ):
        return "base64"


    # Character-separated text.
    if looks_like_spaced(
        text
    ):
        return "spaced"


    # URL percent encoding.
    if URL_PERCENT_PATTERN.search(
        text
    ):
        return "url_percent"


    # ROT13 cannot be reliably detected
    # from surface form alone.
    #
    # Typoglycemia also cannot be
    # deterministically identified.
    #
    # Those should use --representation.
    return "plain"


# ============================================================
# Canonicalizer V4
# ============================================================

def canonicalize_text(
    raw_text,
    representation_hint="auto",
    verbose=True,
):

    if representation_hint not in (
        SUPPORTED_REPRESENTATIONS
    ):
        raise ValueError(
            f"Unsupported representation: "
            f"{representation_hint}"
        )


    if representation_hint == "auto":
        representation = (
            detect_representation(
                raw_text
            )
        )
    else:
        representation = (
            representation_hint
        )


    if verbose:
        print(
            f"[Gateway] Detected representation: "
            f"{representation}"
        )

        print(
            "[Gateway] Running Canonicalizer V4..."
        )


    result = canonicalizer_v4.canonicalize(
        raw_text,
        representation,
    )


    if not isinstance(
        result,
        dict
    ):
        raise RuntimeError(
            "Canonicalizer V4 returned "
            f"{type(result).__name__}; "
            "expected dict."
        )


    canonical_text = result.get(
        "canonical_text"
    )


    if not isinstance(
        canonical_text,
        str
    ):
        raise RuntimeError(
            "Canonicalizer V4 did not "
            "return canonical_text."
        )


    error = result.get(
        "error"
    )


    if error:
        if verbose:
            print(
                "[Gateway] Canonicalizer error. "
                "Falling back to raw input."
            )

        return {
            "original_text":
                raw_text,

            "canonical_text":
                raw_text,

            "representation":
                representation,

            "changed":
                False,

            "method":
                result.get("method"),

            "error":
                error,

            "details":
                result.get(
                    "details",
                    {}
                ),
        }


    if verbose:
        print(
            f"[Gateway] Canonicalization changed input: "
            f"{bool(result.get('changed'))}"
        )

        print(
            f"[Gateway] Canonicalizer method: "
            f"{result.get('method')}"
        )


    return {
        "original_text":
            raw_text,

        "canonical_text":
            canonical_text,

        "representation":
            result.get(
                "representation",
                representation
            ),

        "changed":
            bool(
                result.get(
                    "changed",
                    canonical_text != raw_text
                )
            ),

        "method":
            result.get("method"),

        "error":
            None,

        "details":
            result.get(
                "details",
                {}
            ),
    }


# ============================================================
# Classifier output parser
# ============================================================

def parse_classifier_output(output):

    if isinstance(output, dict):
        parsed = output

    elif isinstance(output, str):

        text = output.strip()

        if not text:
            return None


        if text.startswith("```"):

            text = re.sub(
                r"^```(?:json)?",
                "",
                text,
                flags=re.IGNORECASE,
            )

            text = re.sub(
                r"```$",
                "",
                text,
            )

            text = text.strip()


        try:
            parsed = json.loads(
                text
            )

        except Exception:
            return None

    else:
        return None


    if not isinstance(
        parsed,
        dict
    ):
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


    if classification not in (
        SECURITY_LEVEL
    ):
        return None


    parsed[
        "classification"
    ] = classification

    return parsed


# ============================================================
# aiXplain execution
# ============================================================

def get_headers():

    api_key = os.getenv(
        "AIXPLAIN_API_KEY"
    )

    if not api_key:
        raise RuntimeError(
            "AIXPLAIN_API_KEY environment "
            "variable is not set."
        )


    return {
        "x-api-key":
            api_key,

        "Content-Type":
            "application/json",
    }


def execute_agent_once(
    text,
    timeout_seconds=180,
    verbose=True,
):

    headers = get_headers()


    if verbose:
        print(
            "[Gateway] Sending text to "
            "AgentShield classifier..."
        )


    response = requests.post(
        AIXPLAIN_RUN_URL,
        headers=headers,
        json={
            "query": text
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
            "aiXplain did not return "
            f"a polling URL: {start}"
        )


    if verbose:
        print(
            f"[Gateway] Request ID: "
            f"{request_id}"
        )

        print(
            "[Gateway] Waiting for "
            "AgentShield result..."
        )


    started = time.time()

    last_progress = -1


    while True:

        elapsed = (
            time.time()
            - started
        )


        if elapsed >= timeout_seconds:

            raise TimeoutError(
                "AgentShield classification "
                f"timed out after "
                f"{timeout_seconds} seconds."
            )


        response = requests.get(
            poll_url,
            headers=headers,
            timeout=60,
        )

        response.raise_for_status()

        result = response.json()


        if result.get(
            "completed"
        ):

            if verbose:
                print(
                    "[Gateway] AgentShield "
                    "result received."
                )

            return (
                request_id,
                result,
            )


        # Progress every ~5 seconds.
        current_progress = int(
            elapsed // 5
        )

        if (
            verbose
            and current_progress
            > last_progress
        ):

            last_progress = (
                current_progress
            )

            print(
                f"[Gateway] Still waiting... "
                f"{int(elapsed)}s"
            )


        time.sleep(2)


def classify(
    text,
    max_attempts=3,
    timeout_seconds=180,
    verbose=True,
):

    total_credits = 0.0
    last_error = None


    for attempt in range(
        1,
        max_attempts + 1
    ):

        if verbose:
            print(
                f"[Gateway] Classification "
                f"attempt {attempt}/"
                f"{max_attempts}"
            )


        try:

            (
                request_id,
                result,
            ) = execute_agent_once(
                text,
                timeout_seconds=(
                    timeout_seconds
                ),
                verbose=verbose,
            )


            status = result.get(
                "status"
            )

            data = result.get(
                "data",
                {}
            )


            credits = float(
                data.get(
                    "usedCredits",
                    0
                )
                or 0
            )

            total_credits += (
                credits
            )


            output = data.get(
                "output"
            )

            parsed = (
                parse_classifier_output(
                    output
                )
            )


            if (
                status == "SUCCESS"
                and parsed is not None
            ):

                classification = (
                    parsed[
                        "classification"
                    ]
                )


                if verbose:
                    print(
                        "[Gateway] Classification "
                        f"complete: "
                        f"{classification}"
                    )


                return {
                    "status":
                        "SUCCESS",

                    "request_id":
                        request_id,

                    "classification":
                        classification,

                    "risk_score":
                        parsed.get(
                            "risk_score"
                        ),

                    "attack_types":
                        parsed.get(
                            "attack_types"
                        ),

                    "suspicious_segments":
                        parsed.get(
                            "suspicious_segments"
                        ),

                    "explanation":
                        parsed.get(
                            "explanation"
                        ),

                    "recommended_action":
                        parsed.get(
                            "recommended_action"
                        ),

                    "policy_action":
                        POLICY_ACTION[
                            classification
                        ],

                    "runtime":
                        data.get(
                            "runTime"
                        ),

                    "used_credits":
                        total_credits,

                    "attempts":
                        attempt,
                }


            last_error = {
                "status":
                    status,

                "output":
                    output,

                "error":
                    data.get(
                        "error"
                    ),

                "warnings":
                    data.get(
                        "warnings"
                    ),
            }


            if verbose:
                print(
                    "[Gateway] Agent returned "
                    "an unusable result."
                )


        except Exception as error:

            last_error = {
                "exception":
                    str(error)
            }


            if verbose:
                print(
                    f"[Gateway] Attempt failed: "
                    f"{error}"
                )


        if attempt < max_attempts:

            if verbose:
                print(
                    "[Gateway] Retrying in "
                    "2 seconds..."
                )

            time.sleep(2)


    return {
        "status":
            "FAILED",

        "request_id":
            None,

        "classification":
            None,

        "risk_score":
            None,

        "policy_action":
            "ERROR",

        "runtime":
            None,

        "used_credits":
            total_credits,

        "attempts":
            max_attempts,

        "error":
            last_error,
    }


# ============================================================
# Raw vs canonical comparison
# ============================================================

def compare_decisions(
    raw_classification,
    canonical_classification,
):

    if (
        raw_classification is None
        or canonical_classification is None
    ):

        return {
            "disagreement":
                None,

            "direction":
                "UNAVAILABLE",

            "finding":
                "EXECUTION_FAILURE",
        }


    if (
        raw_classification
        == canonical_classification
    ):

        return {
            "disagreement":
                False,

            "direction":
                "STABLE",

            "finding":
                "NO_DECISION_CHANGE",
        }


    raw_level = SECURITY_LEVEL[
        raw_classification
    ]

    canonical_level = SECURITY_LEVEL[
        canonical_classification
    ]


    if raw_level > canonical_level:

        direction = (
            "RAW_MORE_DEFENSIVE"
        )

    else:

        direction = (
            "CANONICAL_MORE_DEFENSIVE"
        )


    # Production traffic has no known
    # ground truth, so do not label this
    # automatically as over/under-defense.
    return {
        "disagreement":
            True,

        "direction":
            direction,

        "finding":
            "RAW_CANONICAL_DISAGREEMENT",
    }


# ============================================================
# Production mode
# ============================================================

def production_scan(
    raw_text,
    representation_hint="auto",
    timeout_seconds=180,
    verbose=True,
):

    scan_id = (
        "ASG-"
        + uuid.uuid4().hex[:12]
    )

    started = time.time()


    if verbose:
        print("=" * 78)

        print(
            "AgentShield Gateway — "
            "PRODUCTION MODE"
        )

        print("=" * 78)


    canonical = canonicalize_text(
        raw_text,
        representation_hint=(
            representation_hint
        ),
        verbose=verbose,
    )


    canonical_text = canonical[
        "canonical_text"
    ]


    if verbose:
        print(
            "[Gateway] Classifying "
            "canonical text..."
        )


    classification = classify(
        canonical_text,
        timeout_seconds=(
            timeout_seconds
        ),
        verbose=verbose,
    )


    gateway_runtime = (
        time.time()
        - started
    )


    return {
        "scan_id":
            scan_id,

        "mode":
            "production",

        "timestamp":
            now_iso(),

        "canonicalization": {
            "representation":
                canonical.get(
                    "representation"
                ),

            "changed":
                canonical.get(
                    "changed"
                ),

            "method":
                canonical.get(
                    "method"
                ),

            "error":
                canonical.get(
                    "error"
                ),
        },

        "decision": {
            "classification":
                classification.get(
                    "classification"
                ),

            "risk_score":
                classification.get(
                    "risk_score"
                ),

            "action":
                classification.get(
                    "policy_action"
                ),

            "attack_types":
                classification.get(
                    "attack_types"
                ),

            "explanation":
                classification.get(
                    "explanation"
                ),

            "recommended_action":
                classification.get(
                    "recommended_action"
                ),
        },

        "execution": {
            "status":
                classification.get(
                    "status"
                ),

            "request_id":
                classification.get(
                    "request_id"
                ),

            "attempts":
                classification.get(
                    "attempts"
                ),

            "used_credits":
                classification.get(
                    "used_credits",
                    0
                ),

            "model_runtime":
                classification.get(
                    "runtime"
                ),

            "gateway_runtime":
                gateway_runtime,
        },

        "input": {
            "raw_sha256":
                sha256_text(
                    raw_text
                ),

            "canonical_sha256":
                sha256_text(
                    canonical_text
                ),

            "raw_length":
                len(
                    raw_text
                ),

            "canonical_length":
                len(
                    canonical_text
                ),
        },

        "_raw_text":
            raw_text,

        "_canonical_text":
            canonical_text,
    }


# ============================================================
# Audit mode
# ============================================================

def audit_scan(
    raw_text,
    representation_hint="auto",
    timeout_seconds=180,
    verbose=True,
):

    scan_id = (
        "ASA-"
        + uuid.uuid4().hex[:12]
    )

    started = time.time()


    if verbose:
        print("=" * 78)

        print(
            "AgentShield Gateway — "
            "AUDIT MODE"
        )

        print("=" * 78)


    canonical = canonicalize_text(
        raw_text,
        representation_hint=(
            representation_hint
        ),
        verbose=verbose,
    )


    canonical_text = canonical[
        "canonical_text"
    ]


    if verbose:
        print()
        print(
            "[Gateway] AUDIT VIEW 1/2: "
            "classifying RAW input..."
        )


    raw_result = classify(
        raw_text,
        timeout_seconds=(
            timeout_seconds
        ),
        verbose=verbose,
    )


    if verbose:
        print()
        print(
            "[Gateway] AUDIT VIEW 2/2: "
            "classifying CANONICAL input..."
        )


    canonical_result = classify(
        canonical_text,
        timeout_seconds=(
            timeout_seconds
        ),
        verbose=verbose,
    )


    comparison = compare_decisions(
        raw_result.get(
            "classification"
        ),
        canonical_result.get(
            "classification"
        ),
    )


    total_credits = (
        float(
            raw_result.get(
                "used_credits",
                0
            )
            or 0
        )
        +
        float(
            canonical_result.get(
                "used_credits",
                0
            )
            or 0
        )
    )


    gateway_runtime = (
        time.time()
        - started
    )


    return {
        "scan_id":
            scan_id,

        "mode":
            "audit",

        "timestamp":
            now_iso(),

        "canonicalization": {
            "representation":
                canonical.get(
                    "representation"
                ),

            "changed":
                canonical.get(
                    "changed"
                ),

            "method":
                canonical.get(
                    "method"
                ),

            "error":
                canonical.get(
                    "error"
                ),
        },

        "raw_view": {
            "classification":
                raw_result.get(
                    "classification"
                ),

            "risk_score":
                raw_result.get(
                    "risk_score"
                ),

            "action":
                raw_result.get(
                    "policy_action"
                ),

            "status":
                raw_result.get(
                    "status"
                ),

            "request_id":
                raw_result.get(
                    "request_id"
                ),
        },

        "canonical_view": {
            "classification":
                canonical_result.get(
                    "classification"
                ),

            "risk_score":
                canonical_result.get(
                    "risk_score"
                ),

            "action":
                canonical_result.get(
                    "policy_action"
                ),

            "status":
                canonical_result.get(
                    "status"
                ),

            "request_id":
                canonical_result.get(
                    "request_id"
                ),
        },

        "comparison":
            comparison,

        "production_decision": {
            "classification":
                canonical_result.get(
                    "classification"
                ),

            "action":
                canonical_result.get(
                    "policy_action"
                ),
        },

        "execution": {
            "used_credits":
                total_credits,

            "gateway_runtime":
                gateway_runtime,
        },

        "input": {
            "raw_sha256":
                sha256_text(
                    raw_text
                ),

            "canonical_sha256":
                sha256_text(
                    canonical_text
                ),

            "raw_length":
                len(
                    raw_text
                ),

            "canonical_length":
                len(
                    canonical_text
                ),
        },

        "_raw_text":
            raw_text,

        "_canonical_text":
            canonical_text,
    }


# ============================================================
# Logging
# ============================================================

def build_log_record(
    result,
    include_content=False,
):

    record = dict(
        result
    )

    raw_text = record.pop(
        "_raw_text",
        None
    )

    canonical_text = record.pop(
        "_canonical_text",
        None
    )


    if include_content:

        record[
            "content"
        ] = {
            "raw_text":
                raw_text,

            "canonical_text":
                canonical_text,
        }


    return record


# ============================================================
# Console output
# ============================================================

def print_summary(result):

    print()
    print("=" * 78)

    print(
        "AGENTSHIELD GATEWAY RESULT"
    )

    print("=" * 78)

    print(
        f"Scan ID: "
        f"{result['scan_id']}"
    )

    print(
        f"Mode: "
        f"{result['mode']}"
    )

    print(
        f"Representation: "
        f"{result['canonicalization']['representation']}"
    )

    print(
        f"Canonicalization changed input: "
        f"{result['canonicalization']['changed']}"
    )

    print(
        f"Canonicalizer method: "
        f"{result['canonicalization']['method']}"
    )


    if result[
        "mode"
    ] == "production":

        decision = result[
            "decision"
        ]

        print()
        print(
            f"Classification: "
            f"{decision['classification']}"
        )

        print(
            f"Risk score: "
            f"{decision['risk_score']}"
        )

        print(
            f"Policy action: "
            f"{decision['action']}"
        )


    else:

        print()

        print(
            f"Raw classification: "
            f"{result['raw_view']['classification']}"
        )

        print(
            f"Canonical classification: "
            f"{result['canonical_view']['classification']}"
        )

        print()

        print(
            f"Disagreement: "
            f"{result['comparison']['disagreement']}"
        )

        print(
            f"Direction: "
            f"{result['comparison']['direction']}"
        )

        print(
            f"Finding: "
            f"{result['comparison']['finding']}"
        )

        print()

        print(
            f"Production action: "
            f"{result['production_decision']['action']}"
        )


    print()

    print(
        f"Credits used: "
        f"{result['execution'].get('used_credits', 0):.6f}"
    )

    print(
        f"Gateway runtime: "
        f"{result['execution'].get('gateway_runtime', 0):.2f}s"
    )

    print("=" * 78)


# ============================================================
# Input
# ============================================================

def resolve_input(args):

    if args.text is not None:
        return args.text


    if args.file is not None:

        path = Path(
            args.file
        )

        if not path.exists():

            raise FileNotFoundError(
                f"Input file not found: "
                f"{path}"
            )


        return path.read_text(
            encoding="utf-8"
        )


    raise RuntimeError(
        "Provide --text or --file."
    )


# ============================================================
# Main
# ============================================================

def main():

    parser = argparse.ArgumentParser(
        description=(
            "AgentShield Representation-Aware "
            "LLM Security Gateway"
        )
    )


    parser.add_argument(
        "mode",
        choices=[
            "production",
            "audit",
        ],
    )


    input_group = (
        parser.add_mutually_exclusive_group(
            required=True
        )
    )


    input_group.add_argument(
        "--text",
        type=str,
    )


    input_group.add_argument(
        "--file",
        type=str,
    )


    parser.add_argument(
        "--representation",
        default="auto",
        choices=sorted(
            SUPPORTED_REPRESENTATIONS
        ),
        help=(
            "Representation hint. "
            "Use auto normally. "
            "ROT13 and typoglycemia "
            "should be specified explicitly."
        ),
    )


    parser.add_argument(
        "--timeout",
        type=int,
        default=180,
        help=(
            "Maximum seconds to wait "
            "for each AgentShield call."
        ),
    )


    parser.add_argument(
        "--no-log",
        action="store_true",
    )


    parser.add_argument(
        "--log-content",
        action="store_true",
    )


    parser.add_argument(
        "--json-only",
        action="store_true",
    )


    args = parser.parse_args()

    raw_text = resolve_input(
        args
    )


    verbose = (
        not args.json_only
    )


    if args.mode == "production":

        result = production_scan(
            raw_text,
            representation_hint=(
                args.representation
            ),
            timeout_seconds=(
                args.timeout
            ),
            verbose=verbose,
        )

    else:

        result = audit_scan(
            raw_text,
            representation_hint=(
                args.representation
            ),
            timeout_seconds=(
                args.timeout
            ),
            verbose=verbose,
        )


    log_record = build_log_record(
        result,
        include_content=(
            args.log_content
        ),
    )


    if not args.no_log:

        append_jsonl(
            AUDIT_LOG_FILE,
            log_record,
        )


    if verbose:

        print_summary(
            result
        )

        print()

        print(
            "Full JSON:"
        )


    printable = build_log_record(
        result,
        include_content=True,
    )


    print(
        json.dumps(
            printable,
            ensure_ascii=False,
            indent=2,
        )
    )


    if (
        verbose
        and not args.no_log
    ):

        print()

        print(
            f"Audit log: "
            f"{AUDIT_LOG_FILE}"
        )


if __name__ == "__main__":
    main()