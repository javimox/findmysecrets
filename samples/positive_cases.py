"""Cases that FindMySecrets MUST report. Every value is made up.

Each line with a secret carries the comment "expected: <rule>"; tests/test_samples.py
checks that the scanner reports exactly those lines and rules.

Tokens with a real provider format (AWS, GitHub, Slack, Stripe, private keys) are
not stored here: samples/make_fake_tokens.py generates them at runtime, so that
GitHub push protection does not block the push.
"""

# Classic constant assignment
DB_PASSWORD = "Pr0d-Db-2026!"  # expected: hardcoded-credential

# API key: also high entropy, but the more specific rule wins
API_KEY = "k7Qe9xLm2Rw4Tz8Vb3Nh"  # expected: hardcoded-credential

# Keys inside a dictionary (same as JSON)
SETTINGS = {
    "client_secret": "cs-4f1e9a7b-prod",  # expected: hardcoded-credential
    "smtp_passwd": "Mail!Relay#77",  # expected: hardcoded-credential
}


class Config:
    # Type annotation with a default value (dataclasses, pydantic...)
    auth_token: str = "tok-3f9a-77c1-b2e4"  # expected: hardcoded-credential


def is_admin(password):
    # Comparison with a literal: the password is still in the code
    return password == "letmein2026"  # expected: hardcoded-credential


# Connection string with user:password
DATABASE_URL = "postgresql://app:Sup3rS3cret@db.internal:5432/app"  # expected: connection-string

# Random token without any keyword in its name: only entropy gives it away
UPLOAD_SIGNATURE = "Xk29fLq8ZpR4mW7vB2nT6yH3"  # expected: high-entropy-string
