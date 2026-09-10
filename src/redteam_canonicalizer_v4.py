import base64
import binascii
import codecs
import html
import re
from urllib.parse import unquote

try:
    from typoglycemia_normalizer import normalize_typoglycemia
except ImportError:
    normalize_typoglycemia = None


SUPPORTED_REPRESENTATIONS = {
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


def _result(
    original,
    canonical,
    representation,
    method,
    error=None,
    details=None,
):
    return {
        "original_text": original,
        "canonical_text": canonical,
        "representation": representation,
        "changed": canonical != original,
        "method": method,
        "error": error,
        "details": details or {},
    }


# ============================================================
# Plain
# ============================================================

def canonicalize_plain(text):
    return _result(
        text,
        text,
        "plain",
        "identity",
    )


# ============================================================
# Hex
# ============================================================

def canonicalize_hex(text):

    compact = re.sub(
        r"\s+",
        "",
        text,
    )

    if not compact:
        return _result(
            text,
            text,
            "hex",
            "hex_decode",
            error="empty_input",
        )

    if len(compact) % 2 != 0:
        return _result(
            text,
            text,
            "hex",
            "hex_decode",
            error="odd_hex_length",
        )

    if not re.fullmatch(
        r"[0-9A-Fa-f]+",
        compact,
    ):
        return _result(
            text,
            text,
            "hex",
            "hex_decode",
            error="invalid_hex_characters",
        )

    try:
        decoded = (
            bytes.fromhex(
                compact
            )
            .decode(
                "utf-8"
            )
        )

    except (
        ValueError,
        UnicodeDecodeError,
    ) as error:

        return _result(
            text,
            text,
            "hex",
            "hex_decode",
            error=str(error),
        )

    return _result(
        text,
        decoded,
        "hex",
        "hex_decode",
    )


# ============================================================
# Base64
# ============================================================

def canonicalize_base64(text):

    compact = re.sub(
        r"\s+",
        "",
        text,
    )

    if not compact:
        return _result(
            text,
            text,
            "base64",
            "base64_decode",
            error="empty_input",
        )

    try:

        raw = base64.b64decode(
            compact,
            validate=True,
        )

        decoded = raw.decode(
            "utf-8"
        )

    except (
        binascii.Error,
        UnicodeDecodeError,
        ValueError,
    ) as error:

        return _result(
            text,
            text,
            "base64",
            "base64_decode",
            error=str(error),
        )

    return _result(
        text,
        decoded,
        "base64",
        "base64_decode",
    )


# ============================================================
# Spaced
# ============================================================

def canonicalize_spaced(text):

    """
    Example:

    T h e   m u s e u m

    becomes:

    The museum
    """

    if not re.search(
        r"[A-Za-z]\s+[A-Za-z]",
        text,
    ):

        return _result(
            text,
            text,
            "spaced",
            "character_spacing_reconstruction",
            error="spacing_pattern_not_detected",
        )

    chunks = re.split(
        r"\s{2,}",
        text.strip(),
    )

    if len(chunks) < 2:

        return _result(
            text,
            text,
            "spaced",
            "character_spacing_reconstruction",
            error="word_boundaries_not_detected",
        )

    rebuilt_chunks = [
        re.sub(
            r"\s+",
            "",
            chunk,
        )
        for chunk
        in chunks
    ]

    decoded = " ".join(
        rebuilt_chunks
    )

    return _result(
        text,
        decoded,
        "spaced",
        "character_spacing_reconstruction",
    )


# ============================================================
# URL Percent Encoding
# ============================================================

def canonicalize_url_percent(text):

    decoded = unquote(
        text,
        encoding="utf-8",
        errors="strict",
    )

    return _result(
        text,
        decoded,
        "url_percent",
        "url_percent_decode",
    )


# ============================================================
# Unicode Escape
# ============================================================

_UNICODE_ESCAPE_PATTERN = re.compile(
    r"""
    \\u[0-9A-Fa-f]{4}
    |
    \\U[0-9A-Fa-f]{8}
    |
    \\x[0-9A-Fa-f]{2}
    """,
    re.VERBOSE,
)


def canonicalize_unicode_escape(text):

    if not _UNICODE_ESCAPE_PATTERN.search(
        text
    ):

        return _result(
            text,
            text,
            "unicode_escape",
            "unicode_escape_decode",
            error="unicode_escape_pattern_not_detected",
        )

    def replace(match):

        token = match.group(0)

        if token.startswith(
            "\\u"
        ):
            return chr(
                int(
                    token[2:],
                    16,
                )
            )

        if token.startswith(
            "\\U"
        ):

            value = int(
                token[2:],
                16,
            )

            if value > 0x10FFFF:
                raise ValueError(
                    f"invalid_unicode_codepoint:{token}"
                )

            return chr(
                value
            )

        return chr(
            int(
                token[2:],
                16,
            )
        )

    try:

        decoded = (
            _UNICODE_ESCAPE_PATTERN.sub(
                replace,
                text,
            )
        )

    except ValueError as error:

        return _result(
            text,
            text,
            "unicode_escape",
            "unicode_escape_decode",
            error=str(error),
        )

    return _result(
        text,
        decoded,
        "unicode_escape",
        "unicode_escape_decode",
    )


# ============================================================
# HTML Entities
# ============================================================

def canonicalize_html_entities(text):

    decoded = html.unescape(
        text
    )

    return _result(
        text,
        decoded,
        "html_entities",
        "html_entity_decode",
    )


# ============================================================
# ROT13
# ============================================================

def canonicalize_rot13(text):

    decoded = codecs.decode(
        text,
        "rot_13",
    )

    return _result(
        text,
        decoded,
        "rot13",
        "rot13_decode",
    )


# ============================================================
# Typoglycemia
# ============================================================

def canonicalize_typoglycemia(text):

    if normalize_typoglycemia is None:

        return _result(
            text,
            text,
            "typoglycemia",
            "wordfreq_typoglycemia_normalization",
            error=(
                "typoglycemia_normalizer.py "
                "could not be imported"
            ),
        )

    normalized = (
        normalize_typoglycemia(
            text
        )
    )

    return _result(
        text,
        normalized[
            "canonical_text"
        ],
        "typoglycemia",
        "wordfreq_typoglycemia_normalization",
        details={
            "replacement_count":
                normalized.get(
                    "replacement_count",
                    0,
                ),

            "replacements":
                normalized.get(
                    "replacements",
                    [],
                ),
        },
    )


# ============================================================
# Router
# ============================================================

CANONICALIZERS = {
    "plain":
        canonicalize_plain,

    "hex":
        canonicalize_hex,

    "base64":
        canonicalize_base64,

    "spaced":
        canonicalize_spaced,

    "url_percent":
        canonicalize_url_percent,

    "unicode_escape":
        canonicalize_unicode_escape,

    "html_entities":
        canonicalize_html_entities,

    "rot13":
        canonicalize_rot13,

    "typoglycemia":
        canonicalize_typoglycemia,
}


def canonicalize(
    text,
    representation,
):

    representation = (
        representation
        .strip()
        .lower()
    )

    if (
        representation
        not in SUPPORTED_REPRESENTATIONS
    ):

        return _result(
            text,
            text,
            representation,
            "unsupported",
            error=(
                "unsupported_representation:"
                f"{representation}"
            ),
        )

    return CANONICALIZERS[
        representation
    ](
        text
    )


# ============================================================
# Local smoke test
# ============================================================

if __name__ == "__main__":

    examples = [

        (
            "plain",
            "The museum opens at nine.",
        ),

        (
            "hex",
            "546865206d757365756d206f70656e73206174206e696e652e",
        ),

        (
            "base64",
            "VGhlIG11c2V1bSBvcGVucyBhdCBuaW5lLg==",
        ),

        (
            "spaced",
            "T h e   m u s e u m   o p e n s   a t   n i n e .",
        ),

        (
            "url_percent",
            "The%20museum%20opens%20at%20nine.",
        ),

        (
            "unicode_escape",
            r"\u0054\u0068\u0065\u0020\u006d\u0075\u0073\u0065\u0075\u006d",
        ),

        (
            "html_entities",
            "&#84;&#104;&#101;&#32;&#109;&#117;&#115;&#101;&#117;&#109;",
        ),

        (
            "rot13",
            "Gur zhfrhz bcraf ng avar.",
        ),

        (
            "typoglycemia",
            "The sceuirty detector should understand the meaning.",
        ),
    ]

    print(
        "=" * 78
    )

    print(
        "AgentShield Red-Team Canonicalizer V4"
    )

    print(
        "=" * 78
    )

    print()


    for representation, text in examples:

        result = canonicalize(
            text,
            representation,
        )

        print(
            f"{representation}:"
        )

        print(
            f"  Original:  "
            f"{text}"
        )

        print(
            f"  Canonical: "
            f"{result['canonical_text']}"
        )

        print(
            f"  Changed:   "
            f"{result['changed']}"
        )

        print(
            f"  Error:     "
            f"{result['error']}"
        )

        print()