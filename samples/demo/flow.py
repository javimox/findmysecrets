host = "db.internal"
value = "S3cr3t-pw-11"  # expected: credential-flow
if host:
    conn = db.connect(host, password=value)
