import base64
import json
import os
import time

import requests


API_KEY = os.getenv(
    "AIXPLAIN_API_KEY"
)

if not API_KEY:
    raise RuntimeError(
        "AIXPLAIN_API_KEY is not set."
    )


FINAL_AGENT_ID = (
    "6aa05c7ff7ee851ec674682a"
)

CANONICALIZER_TOOL_ID = (
    "6aa0589d32abea90851cd6ec"
)

CANONICALIZER_NAME = (
    "AgentShield Canonicalizer v1"
)


RUN_URL = (
    "https://platform-api.aixplain.com/"
    f"sdk/agents/{FINAL_AGENT_ID}/run"
)

HEADERS = {
    "x-api-key": API_KEY,
    "Content-Type": "application/json",
}


# ============================================================
# Test input
# ============================================================

ORIGINAL_TEXT = (
    "The museum opens at nine in the morning."
)

ENCODED_TEXT = base64.b64encode(
    ORIGINAL_TEXT.encode("utf-8")
).decode("ascii")


print("=" * 78)
print("AgentShield Final — End-to-End Test")
print("=" * 78)

print()
print("Original semantic text:")
print(ORIGINAL_TEXT)

print()
print("Input sent to AgentShield Final:")
print(ENCODED_TEXT)

print()


# ============================================================
# Start agent run
# ============================================================

response = requests.post(
    RUN_URL,
    headers=HEADERS,
    json={
        "query": ENCODED_TEXT
    },
    timeout=30
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
        f"No result URL returned:\n{initial}"
    )


print(
    f"Request ID: {request_id}"
)

print(
    "Waiting for result..."
)


# ============================================================
# Poll
# ============================================================

result = None


for _ in range(90):

    response = requests.get(
        result_url,
        headers=HEADERS,
        timeout=30
    )

    response.raise_for_status()

    result = response.json()


    if result.get("completed") is True:
        break


    time.sleep(1)


else:

    raise RuntimeError(
        "Timed out waiting for result."
    )


print()
print("=" * 78)
print("RUN STATUS")
print("=" * 78)

print(
    f"Status: {result.get('status')}"
)


# ============================================================
# Parse final output
# ============================================================

data = result.get(
    "data",
    {}
)

if not isinstance(data, dict):
    data = {}


output = data.get(
    "output"
)


if isinstance(output, str):

    try:
        parsed_output = json.loads(
            output
        )

    except json.JSONDecodeError:
        parsed_output = output

else:
    parsed_output = output


print()
print("=" * 78)
print("FINAL CLASSIFIER OUTPUT")
print("=" * 78)

print(
    json.dumps(
        parsed_output,
        ensure_ascii=False,
        indent=2
    )
    if isinstance(parsed_output, dict)
    else parsed_output
)


# ============================================================
# Look for evidence of tool execution
# ============================================================

serialized_result = json.dumps(
    result,
    ensure_ascii=False
).lower()


tool_id_found = (
    CANONICALIZER_TOOL_ID.lower()
    in serialized_result
)

tool_name_found = (
    CANONICALIZER_NAME.lower()
    in serialized_result
)

canonical_text_found = (
    ORIGINAL_TEXT.lower()
    in serialized_result
)


print()
print("=" * 78)
print("TOOL EXECUTION EVIDENCE")
print("=" * 78)

print(
    f"Canonicalizer Tool ID found in run trace: "
    f"{tool_id_found}"
)

print(
    f"Canonicalizer name found in run trace: "
    f"{tool_name_found}"
)

print(
    f"Decoded canonical text found in run trace: "
    f"{canonical_text_found}"
)


# ============================================================
# Useful response fields
# ============================================================

print()
print("=" * 78)
print("AVAILABLE RESULT DATA FIELDS")
print("=" * 78)

for key in data.keys():
    print(
        f"- {key}"
    )


print()
print("=" * 78)

if (
    tool_id_found
    or tool_name_found
    or canonical_text_found
):

    print(
        "END-TO-END TOOL EVIDENCE FOUND"
    )

else:

    print(
        "NO TOOL TRACE FOUND IN THIS RESPONSE"
    )

    print(
        "The tool may still have executed, "
        "but the result endpoint may not expose "
        "its trace directly."
    )