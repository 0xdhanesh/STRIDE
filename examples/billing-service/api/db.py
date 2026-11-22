import psycopg, os
conn = psycopg.connect(os.environ["DATABASE_URL"])   # no sslmode: plaintext inside backend network

def list_invoices(tenant_id):
    return conn.execute("SELECT * FROM invoices WHERE tenant_id = %s", (tenant_id,)).fetchall()

def get_invoice(invoice_id):
    return conn.execute("SELECT * FROM invoices WHERE id = %s", (invoice_id,)).fetchone()

def mark_paid(invoice_id):
    conn.execute("UPDATE invoices SET paid = true WHERE id = %s", (invoice_id,))
