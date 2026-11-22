from .db import conn
def audit(actor, action, target):
    conn.execute("INSERT INTO audit_log(actor, action, target) VALUES (%s, %s, %s)", (actor, action, target))
