"""Uses the values of settings.py: FindMySecrets follows the import to the literal."""
import psycopg2

from settings import DB_HOST, DB_TAG


def open_db():
    return psycopg2.connect(host=DB_HOST, user="app", password=DB_TAG)
