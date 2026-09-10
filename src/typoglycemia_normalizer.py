import re
from functools import lru_cache

from wordfreq import top_n_list


# ============================================================
# Configuration
# ============================================================

LANGUAGE = "en"

LEXICON_SIZE = 100_000

MIN_WORD_LENGTH = 5


# ============================================================
# Word helpers
# ============================================================

def word_signature(word):
    """
    Typoglycemia signature:

    first letter
    + sorted internal letters
    + last letter
    + total length

    Example:
        security
        s + ceirtu + y + 8
    """

    word = word.lower()

    if len(word) < MIN_WORD_LENGTH:
        return None

    return (
        word[0],
        "".join(
            sorted(
                word[1:-1]
            )
        ),
        word[-1],
        len(word),
    )


def restore_case(
    original,
    replacement
):
    """
    Preserve simple capitalization patterns.
    """

    if original.isupper():
        return replacement.upper()

    if original.istitle():
        return replacement.title()

    return replacement


# ============================================================
# Build external general-purpose lexicon
# ============================================================

@lru_cache(maxsize=1)
def build_lexicon():

    words = top_n_list(
        LANGUAGE,
        LEXICON_SIZE
    )

    valid_words = []

    known_words = set()

    signature_map = {}


    for rank, word in enumerate(
        words
    ):

        word = word.lower()

        # English alphabetic vocabulary only
        if not word.isascii():
            continue

        if not word.isalpha():
            continue

        if len(word) < MIN_WORD_LENGTH:
            continue


        known_words.add(
            word
        )

        valid_words.append(
            word
        )


        signature = word_signature(
            word
        )


        if signature is None:
            continue


        # top_n_list is already frequency-ranked.
        # First candidate wins deterministically.
        if signature not in signature_map:

            signature_map[
                signature
            ] = word


    return {
        "known_words":
            known_words,

        "signature_map":
            signature_map,

        "lexicon_words":
            len(valid_words),
    }


# ============================================================
# Normalize one word
# ============================================================

def normalize_word(word):

    if len(word) < MIN_WORD_LENGTH:
        return word


    lower = word.lower()


    lexicon = build_lexicon()

    known_words = lexicon[
        "known_words"
    ]

    signature_map = lexicon[
        "signature_map"
    ]


    # --------------------------------------------------------
    # Important safety rule:
    # if it is already a valid dictionary word,
    # leave it unchanged.
    # --------------------------------------------------------

    if lower in known_words:

        return word


    signature = word_signature(
        lower
    )


    if signature is None:

        return word


    candidate = signature_map.get(
        signature
    )


    if candidate is None:

        return word


    return restore_case(
        word,
        candidate
    )


# ============================================================
# Normalize full text
# ============================================================

WORD_PATTERN = re.compile(
    r"[A-Za-z]+"
)


def normalize_typoglycemia(
    text
):

    replacements = []


    def replace(match):

        original_word = (
            match.group(0)
        )

        normalized_word = normalize_word(
            original_word
        )


        if normalized_word != original_word:

            replacements.append({
                "original":
                    original_word,

                "normalized":
                    normalized_word,
            })


        return normalized_word


    canonical_text = (
        WORD_PATTERN.sub(
            replace,
            text
        )
    )


    return {
        "canonical_text":
            canonical_text,

        "changed":
            (
                canonical_text
                != text
            ),

        "replacement_count":
            len(replacements),

        "replacements":
            replacements,

        "method":
            (
                "external_frequency_lexicon_"
                "typoglycemia_signature"
            ),
    }


# ============================================================
# Small local smoke test
# ============================================================

if __name__ == "__main__":

    test = (
        "The sceuirty detector should "
        "understand the semantic meaning."
    )

    result = normalize_typoglycemia(
        test
    )

    print(
        "Original:"
    )

    print(
        test
    )

    print()

    print(
        "Normalized:"
    )

    print(
        result[
            "canonical_text"
        ]
    )

    print()

    print(
        "Replacements:"
    )

    for replacement in result[
        "replacements"
    ]:

        print(
            replacement
        )