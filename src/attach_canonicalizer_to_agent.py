import os

from aixplain import Aixplain


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

TOOL_ID = (
    "6aa0589d32abea90851cd6ec"
)


aix = Aixplain(
    api_key=API_KEY
)


print(
    "Loading AgentShield..."
)

agent = aix.Agent.get(
    AGENT_ID
)


print(
    f"Agent: {agent.name}"
)

print(
    f"Agent ID: {agent.id}"
)


print()
print(
    "Loading canonicalizer tool..."
)

tool = aix.Tool.get(
    TOOL_ID
)


print(
    f"Tool: {tool.name}"
)

print(
    f"Tool ID: {tool.id}"
)


# ============================================================
# Show current tools
# ============================================================

print()
print(
    "CURRENT AGENT TOOLS"
)

print(
    "=" * 70
)


for existing_tool in agent.tools:

    existing_id = getattr(
        existing_tool,
        "id",
        None
    )

    existing_name = getattr(
        existing_tool,
        "name",
        "UNKNOWN"
    )

    print(
        f"- {existing_name} "
        f"({existing_id})"
    )


# ============================================================
# Avoid duplicate attachment
# ============================================================

existing_tool_ids = {
    getattr(
        existing_tool,
        "id",
        None
    )
    for existing_tool
    in agent.tools
}


if TOOL_ID in existing_tool_ids:

    print()
    print(
        "Canonicalizer is already attached."
    )

else:

    print()
    print(
        "Attaching canonicalizer..."
    )

    agent.tools.append(
        tool
    )

    agent.save()

    print(
        "Agent saved."
    )


# ============================================================
# Reload and verify
# ============================================================

agent = aix.Agent.get(
    AGENT_ID
)


print()
print(
    "TOOLS AFTER SAVE"
)

print(
    "=" * 70
)


found = False


for existing_tool in agent.tools:

    existing_id = getattr(
        existing_tool,
        "id",
        None
    )

    existing_name = getattr(
        existing_tool,
        "name",
        "UNKNOWN"
    )

    print(
        f"- {existing_name} "
        f"({existing_id})"
    )


    if existing_id == TOOL_ID:
        found = True


print()
print(
    "=" * 70
)


if found:

    print(
        "SUCCESS"
    )

    print(
        "AgentShield Canonicalizer v1 "
        "is attached to AgentShield."
    )

else:

    raise RuntimeError(
        "Tool was not found on the "
        "agent after save."
    )