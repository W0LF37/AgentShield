import base64
import re


def _mostly_printable(text: str) -> bool:
    if not text:
        return False

    printable = sum(
        1
        for char in text
        if char.isprintable()
        or char in "\n\r\t"
    )

    return (
        printable / len(text)
        >= 0.95
    )


def _try_hex(text: str):
    stripped = text.strip()

    # Strict full-string space-separated hex bytes.
    if not re.fullmatch(
        r"(?:[0-9A-Fa-f]{2})(?:\s+[0-9A-Fa-f]{2})+",
        stripped
    ):
        return None

    try:
        raw = bytes.fromhex(
            stripped
        )

        decoded = raw.decode(
            "utf-8"
        )

    except (
        ValueError,
        UnicodeDecodeError
    ):
        return None

    if not _mostly_printable(
        decoded
    ):
        return None

    return decoded


def _try_base64(text: str):
    stripped = text.strip()

    # Conservative full-string Base64 detection.
    if len(stripped) < 16:
        return None

    if len(stripped) % 4 != 0:
        return None

    if not re.fullmatch(
        r"[A-Za-z0-9+/]+={0,2}",
        stripped
    ):
        return None

    try:
        raw = base64.b64decode(
            stripped,
            validate=True
        )

        decoded = raw.decode(
            "utf-8"
        )

    except (
        ValueError,
        UnicodeDecodeError,
        base64.binascii.Error
    ):
        return None

    if not _mostly_printable(
        decoded
    ):
        return None

    return decoded


def _try_spaced(text: str):
    # Transformation used by AgentShield-ObfusBench:
    # every original character separated by exactly one space.
    #
    # Example:
    # H e l l o
    # -> Hello

    if len(text) < 3:
        return None

    if len(text) % 2 == 0:
        return None

    # Every odd position must be exactly one space.
    for index in range(
        1,
        len(text),
        2
    ):
        if text[index] != " ":
            return None

    recovered = text[::2]

    if not recovered.strip():
        return None

    return recovered


def canonicalize_input(text: str):
    """
    Normalize representation-level transformations before
    prompt-injection classification.

    Supported:
    - Hexadecimal UTF-8 byte representation
    - Base64 UTF-8 representation
    - Character-spaced text

    Plain text is preserved unchanged.

    Returns a JSON-serializable dictionary.
    """

    if not isinstance(
        text,
        str
    ):
        return {
            "canonical_text": "",
            "detected_representation": "invalid",
            "changed": 0,
            "error": "Input must be a string."
        }

    original = text

    # --------------------------------------------------------
    # Hex
    # --------------------------------------------------------

    decoded = _try_hex(
        original
    )

    if decoded is not None:
        return {
            "canonical_text":
                decoded,

            "detected_representation":
                "hex",

            "changed":
                1,

            "error":
                None
        }

    # --------------------------------------------------------
    # Base64
    # --------------------------------------------------------

    decoded = _try_base64(
        original
    )

    if decoded is not None:
        return {
            "canonical_text":
                decoded,

            "detected_representation":
                "base64",

            "changed":
                1,

            "error":
                None
        }

    # --------------------------------------------------------
    # Spaced
    # --------------------------------------------------------

    decoded = _try_spaced(
        original
    )

    if decoded is not None:
        return {
            "canonical_text":
                decoded,

            "detected_representation":
                "spaced",

            "changed":
                1,

            "error":
                None
        }

    # --------------------------------------------------------
    # Plain / unsupported representation
    # --------------------------------------------------------

    return {
        "canonical_text":
            original,

        "detected_representation":
            "plain",

        "changed":
            0,

        "error":
            None
    }