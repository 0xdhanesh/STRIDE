from fastapi import FastAPI, Depends, Request
from .auth import require_user, require_role
from .db import get_invoice, list_invoices, mark_paid
from .payments import charge, verify_webhook
from .audit import audit
import redis, os

app = FastAPI()
cache = redis.from_url(os.environ["REDIS_URL"])

@app.get("/invoices")
def invoices(user=Depends(require_user)):
    return list_invoices(user.tenant_id)

@app.get("/invoices/{invoice_id}")
def invoice(invoice_id: str, user=Depends(require_user)):
    return get_invoice(invoice_id)            # NOTE: no tenant check

@app.post("/invoices/{invoice_id}/pay")
def pay(invoice_id: str, user=Depends(require_role("billing"))):
    result = charge(invoice_id)
    audit(user.id, "invoice.pay", invoice_id)
    cache.rpush("jobs:receipts", invoice_id)  # worker sends the receipt
    return result

@app.post("/webhooks/stripe")
async def stripe_webhook(request: Request):
    event = verify_webhook(await request.body(), request.headers.get("Stripe-Signature"))
    mark_paid(event["data"]["object"]["metadata"]["invoice_id"])
    return {"ok": True}
