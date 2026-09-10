import os
from pathlib import Path

from aixplain import Aixplain


API_KEY = os.getenv(
    "AIXPLAIN_API_KEY"
)

if not API_KEY:
    raise RuntimeError(
        "AIXPLAIN_API_KEY is not set."
    )


SOURCE_FILE = (
    Path(__file__).resolve().parent
    / "agentshield_canonicalizer_tool.py"
)


if not SOURCE_FILE.exists():
    raise FileNotFoundError(
        f"Canonicalizer file not found:\n"
        f"{SOURCE_FILE}"
    )


with SOURCE_FILE.open(
    "r",
    encoding="utf-8"
) as file:

    script_content = file.read()


aix = Aixplain(
    api_key=API_KEY
)


print(
    "Creating AgentShield Canonicalizer..."
)


tool = aix.Tool(
    name="AgentShield Canonicalizer v1",

    description=(
        "Deterministically canonicalizes "
        "untrusted text before prompt-injection "
        "classification. Supports Hex, Base64, "
        "and character-spaced representations."
    ),

    integration=(
        "688779d8bfb8e46c273982ca"
    ),

    config={
        "code":
            script_content,

        "function_name":
            "canonicalize_input",
    },
)


tool.save()


print()
print(
    "TOOL CREATED"
)

print(
    f"Tool ID: {tool.id}"
)

print(
    f"Tool name: {tool.name}"
)


# ============================================================
# Smoke tests
# ============================================================

tests = {
    "plain":
        "The museum opens at nine.",

    "base64":
        "VGhlIG11c2V1bSBvcGVucyBhdCBuaW5lLg==",

    "hex":
        (
            "54 68 65 20 6d 75 73 65 75 6d "
            "20 6f 70 65 6e 73 20 61 74 20 "
            "6e 69 6e 65 2e"
        ),

    "spaced":
        "H e l l o",
}


print()
print(
    "=" * 70
)

print(
    "TOOL SMOKE TEST"
)

print(
    "=" * 70
)


for test_name, text in tests.items():

    print()
    print(
        f"TEST: {test_name}"
    )

    result = tool.run(
        action="canonicalize_input",

        data={
            "text":
                text
        },
    )

    print(
        result.data
    )