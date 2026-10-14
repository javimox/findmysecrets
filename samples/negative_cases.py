"""Cases that FindMySecrets must NOT report.

Not-a-secret signals (module book, p. 65): placeholders, references to secret
managers and obviously public data (commit hashes, checksums, ids). No line of
this file may appear in a report.
"""
import getpass
import os

# The secret is read from the environment or typed by the user: not in the code
API_KEY = os.environ["API_KEY"]
DB_PASSWORD = os.getenv("DB_PASSWORD", "")
user_password = getpass.getpass("Password: ")

# Placeholders
SMTP_PASSWORD = "YOUR_SMTP_PASSWORD"
GITHUB_TOKEN = "<TOKEN>"
WEBHOOK_SECRET = "changeme"
STRIPE_API_KEY = "xxxxxxxxxxxxxxxxxxxxxxxx"
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"  # AWS documentation example key

# References to variables, templates and secret managers
ADMIN_PASSWORD = "${ADMIN_PASSWORD}"
DB_SECRET = "vault:secret/data/app"
RDS_PASSWORD = "arn:aws:secretsmanager:eu-west-1:123456789012:secret:rds"

# Field names, URLs and metadata, not secret values
PASSWORD_FIELD = "password"
TOKEN_URL = "https://auth.acme.test/oauth/token"
SECRET_NAME = "prod/app/db"
MIN_PASSWORD_LENGTH = 12

# Public data that looks random
COMMIT = "9fceb02d0ae598e95dc970b74767f19372d61af8"  # commit hash
CHECKSUM = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"  # sha256
REQUEST_ID = "3f2b8c1e-4d5a-4b6c-9e7f-1a2b3c4d5e6f"  # UUID
HANDLER = "NotificationDispatcherService2"  # long identifier


# Same name, different scopes: the function uses its own value from the environment
default_value = "documentation-only"


def connect():
    default_value = os.environ["DB_PASSWORD"]
    return db.connect(password=default_value)


# Keyword arguments that merely contain "auth" or "token" are not credentials
writer = "Jane-Austen-1775"
model_name = "bert-base-uncased"
book = Book(title="Emma", author=writer)
pipe = pipeline("ner", tokenizer=model_name)
