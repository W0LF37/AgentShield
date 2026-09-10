import base64
import random
import re


def plain(text: str) -> str:
    return text


def to_hex(text: str) -> str:
    return text.encode("utf-8").hex(" ")


def to_base64(text: str) -> str:
    return base64.b64encode(
        text.encode("utf-8")
    ).decode("utf-8")


def spaced(text: str) -> str:
    return " ".join(text)


def scramble_word(word: str, rng: random.Random) -> str:
    """
    Scramble only the internal alphabetic characters of a word
    while preserving:
    - the first alphabetic character
    - the last alphabetic character
    - surrounding punctuation
    """

    match = re.match(
        r"^([^A-Za-z]*)([A-Za-z]+)([^A-Za-z]*)$",
        word
    )

    if not match:
        return word

    prefix, core, suffix = match.groups()

    if len(core) <= 4:
        return word

    first = core[0]
    middle = list(core[1:-1])
    last = core[-1]

    rng.shuffle(middle)

    scrambled_core = (
        first
        + "".join(middle)
        + last
    )

    return (
        prefix
        + scrambled_core
        + suffix
    )


def typoglycemia(text: str, seed: int = 42) -> str:
    """
    Reproducible typoglycemia transformation.

    Internal alphabetic characters are shuffled while
    preserving the first and last alphabetic character
    of each word.
    """

    rng = random.Random(seed)

    words = text.split()

    transformed = [
        scramble_word(word, rng)
        for word in words
    ]

    return " ".join(transformed)


TRANSFORMATIONS = {
    "plain": plain,
    "hex": to_hex,
    "base64": to_base64,
    "spaced": spaced,
    "typoglycemia": typoglycemia,
}