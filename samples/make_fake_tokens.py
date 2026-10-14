"""Generate FAKE tokens with each provider's real format (module book, p. 65).

They are never stored in the repository: GitHub push protection would block a
push containing a token with a real format, even an invented one. The tests use
these same functions at runtime.

Usage:
    python samples/make_fake_tokens.py      # writes samples/generated/fake_tokens.txt
    findmysecrets scan samples/generated
"""
from __future__ import annotations

import random
import string
from pathlib import Path

ALNUM = string.ascii_letters + string.digits
UPPER_DIGITS = string.ascii_uppercase + string.digits
B64 = ALNUM + "+/"

# Built in pieces so that this file does not contain the literal header.
PEM_BEGIN = "-----BEGIN " + "RSA PRIVATE KEY" + "-----"
PEM_END = "-----END " + "RSA PRIVATE KEY" + "-----"


def fake_tokens(seed: int = 2026) -> list[tuple[str, str]]:
    """(rule that must fire, line holding a fake token)."""
    rnd = random.Random(seed)

    def r(n: int, alphabet: str = ALNUM) -> str:
        return "".join(rnd.choice(alphabet) for _ in range(n))

    return [
        ("aws-access-key-id", "aws " + "AKIA" + r(16, UPPER_DIGITS)),
        ("aws-access-key-id", "aws sts " + "ASIA" + r(16, UPPER_DIGITS)),
        ("github-token", "github " + "ghp" + "_" + r(36)),
        ("github-token", "github fine-grained " + "github" + "_pat_" + r(22) + "_" + r(59)),
        ("slack-token", "slack bot " + "xox" + "b-" + r(12, string.digits) + "-" + r(13, string.digits) + "-" + r(24)),
        ("slack-token", "slack user " + "xox" + "p-" + r(12, string.digits) + "-" + r(13, string.digits) + "-" + r(32)),
        ("stripe-key", "stripe " + "sk" + "_live_" + r(24)),
        ("stripe-key", "stripe restricted " + "rk" + "_live_" + r(24)),
        ("private-key", PEM_BEGIN),
    ]


def fake_pem(seed: int = 2026) -> str:
    """A complete PEM block with random base64 (not a valid key)."""
    rnd = random.Random(seed)
    body = ["".join(rnd.choice(B64) for _ in range(64)) for _ in range(6)]
    return "\n".join([PEM_BEGIN, *body, PEM_END])


def main() -> Path:
    out = Path(__file__).resolve().parent / "generated" / "fake_tokens.txt"
    out.parent.mkdir(exist_ok=True)
    lines = [line for _, line in fake_tokens() if not line.startswith("-----")]
    out.write_text("\n".join(lines) + "\n\n" + fake_pem() + "\n", encoding="utf-8")
    return out


if __name__ == "__main__":
    print(main())
