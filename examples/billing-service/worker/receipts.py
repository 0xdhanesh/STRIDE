import redis, smtplib, os
from api.db import get_invoice
r = redis.from_url(os.environ["REDIS_URL"])
while True:
    _, invoice_id = r.blpop("jobs:receipts")
    inv = get_invoice(invoice_id)
    with smtplib.SMTP("smtp.sendgrid.net", 587) as s:
        s.starttls()
        s.sendmail("billing@acme.test", inv["email"], render(inv))
