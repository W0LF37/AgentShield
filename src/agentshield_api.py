import os
import time
from typing import Literal

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

import agentshield_gateway as gateway


# ============================================================
# Configuration
# ============================================================

API_VERSION = "1.0.0"

MAX_INPUT_LENGTH = int(
    os.getenv(
        "AGENTSHIELD_MAX_INPUT_LENGTH",
        "32000",
    )
)


# ============================================================
# FastAPI application
# ============================================================

app = FastAPI(
    title="AgentShield Security Gateway",
    description=(
        "Representation-aware LLM security gateway "
        "for prompt-injection classification, "
        "canonicalization, policy enforcement, "
        "and raw-vs-canonical audit analysis."
    ),
    version=API_VERSION,
)


# ============================================================
# Request schemas
# ============================================================

Representation = Literal[
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
]


class ScanRequest(BaseModel):

    text: str = Field(
        ...,
        min_length=1,
        description=(
            "Untrusted text to inspect."
        ),
    )

    representation: Representation = Field(
        default="auto",
        description=(
            "Representation hint. "
            "Use auto normally. "
            "ROT13 and typoglycemia should "
            "normally be supplied explicitly."
        ),
    )

    timeout: int = Field(
        default=60,
        ge=15,
        le=180,
        description=(
            "Maximum number of seconds "
            "for each classifier attempt."
        ),
    )

    include_content: bool = Field(
        default=False,
        description=(
            "Return raw and canonical text "
            "in the API response. "
            "Disabled by default."
        ),
    )


class AuditRequest(BaseModel):

    text: str = Field(
        ...,
        min_length=1,
        description=(
            "Untrusted text to inspect."
        ),
    )

    representation: Representation = Field(
        default="auto",
    )

    timeout: int = Field(
        default=60,
        ge=15,
        le=180,
    )

    include_content: bool = Field(
        default=False,
    )


# ============================================================
# Helpers
# ============================================================

def validate_input(text: str):

    if not text.strip():

        raise HTTPException(
            status_code=400,
            detail=(
                "Input text cannot be empty."
            ),
        )


    if len(text) > MAX_INPUT_LENGTH:

        raise HTTPException(
            status_code=413,
            detail=(
                f"Input exceeds maximum length "
                f"of {MAX_INPUT_LENGTH} characters."
            ),
        )


def make_public_result(
    result,
    include_content=False,
):

    public = dict(
        result
    )


    raw_text = public.pop(
        "_raw_text",
        None,
    )

    canonical_text = public.pop(
        "_canonical_text",
        None,
    )


    if include_content:

        public[
            "content"
        ] = {
            "raw_text":
                raw_text,

            "canonical_text":
                canonical_text,
        }


    return public


def persist_audit_record(
    result,
):

    # Security default:
    #
    # Store metadata + hashes only.
    # Raw user content is NOT persisted.
    record = gateway.build_log_record(
        result,
        include_content=False,
    )


    gateway.append_jsonl(
        gateway.AUDIT_LOG_FILE,
        record,
    )


def ensure_gateway_success(
    result,
):

    mode = result.get(
        "mode"
    )


    if mode == "production":

        execution_status = (
            result
            .get(
                "execution",
                {}
            )
            .get(
                "status"
            )
        )


        if execution_status != "SUCCESS":

            raise HTTPException(
                status_code=502,
                detail={
                    "message":
                        (
                            "AgentShield classifier "
                            "did not return a usable result."
                        ),

                    "scan_id":
                        result.get(
                            "scan_id"
                        ),

                    "execution":
                        result.get(
                            "execution"
                        ),
                },
            )


    elif mode == "audit":

        raw_status = (
            result
            .get(
                "raw_view",
                {}
            )
            .get(
                "status"
            )
        )


        canonical_status = (
            result
            .get(
                "canonical_view",
                {}
            )
            .get(
                "status"
            )
        )


        if (
            raw_status != "SUCCESS"
            or canonical_status != "SUCCESS"
        ):

            raise HTTPException(
                status_code=502,
                detail={
                    "message":
                        (
                            "One or more audit "
                            "classifier views failed."
                        ),

                    "scan_id":
                        result.get(
                            "scan_id"
                        ),

                    "raw_status":
                        raw_status,

                    "canonical_status":
                        canonical_status,
                },
            )


# ============================================================
# Root
# ============================================================

@app.get("/")
def root():

    return {
        "service":
            "AgentShield Security Gateway",

        "version":
            API_VERSION,

        "status":
            "running",

        "endpoints": {
            "health":
                "/health",

            "production_scan":
                "/scan",

            "audit":
                "/audit",

            "interactive_docs":
                "/docs",
        },
    }


# ============================================================
# Health
# ============================================================

@app.get("/health")
def health():

    api_key_configured = bool(
        os.getenv(
            "AIXPLAIN_API_KEY"
        )
    )


    return {
        "status":
            (
                "healthy"
                if api_key_configured
                else "degraded"
            ),

        "service":
            "AgentShield Security Gateway",

        "version":
            API_VERSION,

        "classifier_agent_id":
            gateway.CLASSIFIER_AGENT_ID,

        "canonicalizer":
            "V4",

        "api_key_configured":
            api_key_configured,

        "max_input_length":
            MAX_INPUT_LENGTH,

        "policy": {
            "SAFE":
                "ALLOW",

            "SUSPICIOUS":
                "REVIEW",

            "MALICIOUS":
                "BLOCK",
        },
    }


# ============================================================
# Production scan
# ============================================================

@app.post("/scan")
def scan(
    request: ScanRequest,
):

    validate_input(
        request.text
    )


    started = time.time()


    try:

        result = gateway.production_scan(
            request.text,
            representation_hint=(
                request.representation
            ),
            timeout_seconds=(
                request.timeout
            ),
            verbose=False,
        )


        ensure_gateway_success(
            result
        )


        persist_audit_record(
            result
        )


        response = make_public_result(
            result,
            include_content=(
                request.include_content
            ),
        )


        response[
            "api"
        ] = {
            "version":
                API_VERSION,

            "endpoint":
                "/scan",

            "request_runtime_seconds":
                (
                    time.time()
                    - started
                ),
        }


        return response


    except HTTPException:

        raise


    except Exception as error:

        raise HTTPException(
            status_code=500,
            detail={
                "message":
                    (
                        "AgentShield production "
                        "scan failed."
                    ),

                "error":
                    str(error),
            },
        )


# ============================================================
# Audit scan
# ============================================================

@app.post("/audit")
def audit(
    request: AuditRequest,
):

    validate_input(
        request.text
    )


    started = time.time()


    try:

        result = gateway.audit_scan(
            request.text,
            representation_hint=(
                request.representation
            ),
            timeout_seconds=(
                request.timeout
            ),
            verbose=False,
        )


        ensure_gateway_success(
            result
        )


        persist_audit_record(
            result
        )


        response = make_public_result(
            result,
            include_content=(
                request.include_content
            ),
        )


        response[
            "api"
        ] = {
            "version":
                API_VERSION,

            "endpoint":
                "/audit",

            "request_runtime_seconds":
                (
                    time.time()
                    - started
                ),
        }


        return response


    except HTTPException:

        raise


    except Exception as error:

        raise HTTPException(
            status_code=500,
            detail={
                "message":
                    (
                        "AgentShield audit "
                        "scan failed."
                    ),

                "error":
                    str(error),
            },
        )


# ============================================================
# Local server entry point
# ============================================================

if __name__ == "__main__":

    import uvicorn


    uvicorn.run(
        "agentshield_api:app",
        host="127.0.0.1",
        port=8000,
        reload=False,
    )