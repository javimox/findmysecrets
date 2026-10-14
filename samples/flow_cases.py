"""Secrets that only the code's logic gives away: names say nothing, uses do.

No regular expression flags these lines; the data-flow analysis follows each
literal to its use. Line markers checked by tests/test_samples.py:
  expected: <rule>   reported without AI (strong use)
  candidate          sent to the decision model (positional argument)
"""
import getpass
import os

import psycopg2
import requests
import smtplib

session_tag = "Zq81-mnbv-2026"  # expected: credential-flow
mailbox = "misecretpass"  # candidate
opts_value = "Xr4-legacy-77"  # candidate
release = "release-2026-10"  # only printed: not a secret
pin = "4471-2210"  # expected: credential-flow
SECRET_KEY = os.environ.get("SECRET_KEY", "django-insecure-dev-only")  # expected: credential-flow


class Repository:
    def open(self):
        return psycopg2.connect(host="db.internal", user="app", password=session_tag)


def notify():
    server = smtplib.SMTP("smtp.acme.test")
    server.login("alerts@acme.test", mailbox)


def call_api():
    token = "tk-" + "91af" + "77bc"  # expected: credential-flow
    headers = {"Authorization": f"Bearer {token}"}
    return requests.get("https://api.acme.test", headers=headers)


def legacy():
    copied = opts_value
    return db.login("admin", copied)


def unlock():
    typed = getpass.getpass("PIN: ")
    return typed == pin


def banner():
    print(release)
