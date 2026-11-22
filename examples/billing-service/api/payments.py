import stripe, os
stripe.api_key = os.environ["STRIPE_API_KEY"]

def charge(invoice_id):
    return stripe.PaymentIntent.create(amount=..., currency="eur", metadata={"invoice_id": invoice_id})

def verify_webhook(payload, signature):
    return stripe.Webhook.construct_event(payload, signature, os.environ["STRIPE_WEBHOOK_SECRET"])
