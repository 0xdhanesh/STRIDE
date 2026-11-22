# Billing service

## Executive summary

Billing service models 11 elements and 16 data flows across 1 diagram; the template produced 97 threats, 94 still open.

25 threats are high signal (backed by source evidence, dangerous sinks or weak controls): Elevation Of Privilege 8, Spoofing 7, Tampering 6, Information Disclosure 4.

71 medium-signal threats and 1 generic threat remain in the full register for architectural review.

**Top findings**

1. Spoofing the Billing SPA process — Spoofing, High priority, Not Started, from Customer to Billing SPA (evidence: web/src/api.ts).
2. Spoofing the Customer external entity — Spoofing, High priority, Not Started, from Customer to Billing SPA (evidence: web/src/api.ts).
3. Potential lack of input validation for Billing SPA — Tampering, High priority, Not Started, from Customer to Billing SPA (evidence: web/src/api.ts).

## High-signal findings

| ID | Finding | Category | Priority | State | Signal | Evidence | Mitigation |
|---:|---|---|---|---|---|---|---|
| 1 | Spoofing the Billing SPA process | Spoofing | High | Not Started | High Signal (50) | web/src/api.ts, web/src/InvoiceView.tsx | Authenticate the destination, for example with TLS server certificates validated against a trusted root, certificate pinning or mutual authentication. |
| 2 | Spoofing the Customer external entity | Spoofing | High | Not Started | High Signal (50) | web/src/api.ts, web/src/InvoiceView.tsx | Require Customer to authenticate (strong passwords plus MFA for people; client certificates, signed tokens or API keys with rotation for systems). |
| 3 | Potential lack of input validation for Billing SPA | Tampering | High | Not Started | High Signal (50) | web/src/api.ts, web/src/InvoiceView.tsx | Validate all input against an allow-list (type, length, format, range) at the boundary and reject anything that does not match. |
| 5 | Data flow sniffing | Information Disclosure | High | Not Started | High Signal (50) | web/src/api.ts, web/src/InvoiceView.tsx | Encrypt the channel (TLS 1.2+, IPsec) and do not send sensitive data that the receiver does not need. |
| 9 | Billing SPA may be subject to elevation of privilege using remote code execution | Elevation Of Privilege | High | Not Started | High Signal (50) | web/src/api.ts, web/src/InvoiceView.tsx | Remove dangerous sinks (eval, shell, unsafe deserialization), validate input, sandbox the process and run it with least privilege. |
| 14 | Weakness in SSO authorization | Elevation Of Privilege | High | Not Started | High Signal (50) | web/src/api.ts, web/src/InvoiceView.tsx, api/auth.py | Validate token signature, issuer, audience and expiry; use exact redirect URIs; use PKCE and state; and grant only the scopes each client needs. |
| 15 | Spoofing the Billing SPA process | Spoofing | High | Not Started | High Signal (50) | web/src/api.ts, web/src/InvoiceView.tsx, docker-compose.yml | Authenticate the calling process with a standard mechanism such as mutual TLS, signed tokens or OS-level service identities, and verify that identity on Gateway. |
| 22 | Gateway may be subject to elevation of privilege using remote code execution | Elevation Of Privilege | High | Not Started | High Signal (50) | web/src/api.ts, web/src/InvoiceView.tsx, docker-compose.yml | Remove dangerous sinks (eval, shell, unsafe deserialization), validate input, sandbox the process and run it with least privilege. |
| 24 | Spoofing the Gateway process | Spoofing | High | Not Started | High Signal (50) | web/src/api.ts, docker-compose.yml, web/src/InvoiceView.tsx | Authenticate the calling process with a standard mechanism such as mutual TLS, signed tokens or OS-level service identities, and verify that identity on Billing SPA. |
| 31 | Billing SPA may be subject to elevation of privilege using remote code execution | Elevation Of Privilege | High | Not Started | High Signal (50) | web/src/api.ts, docker-compose.yml, web/src/InvoiceView.tsx | Remove dangerous sinks (eval, shell, unsafe deserialization), validate input, sandbox the process and run it with least privilege. |
| 33 | Spoofing the Gateway process | Spoofing | High | Not Started | High Signal (50) | docker-compose.yml, api/app.py, api/auth.py | Authenticate the calling process with a standard mechanism such as mutual TLS, signed tokens or OS-level service identities, and verify that identity on Billing API. |
| 35 | Potential lack of input validation for Billing API | Tampering | High | Not Started | High Signal (50) | docker-compose.yml, api/app.py, api/auth.py | Validate all input against an allow-list (type, length, format, range) at the boundary and reject anything that does not match. |
| 42 | Billing API may be subject to elevation of privilege using remote code execution | Elevation Of Privilege | High | Not Started | High Signal (50) | docker-compose.yml, api/app.py, api/auth.py | Remove dangerous sinks (eval, shell, unsafe deserialization), validate input, sandbox the process and run it with least privilege. |
| 44 | Spoofing the Gateway process | Spoofing | High | Not Started | High Signal (50) | api/app.py, api/auth.py, docker-compose.yml | Authenticate the destination, for example with TLS server certificates validated against a trusted root, certificate pinning or mutual authentication. |
| 45 | Potential lack of input validation for Gateway | Tampering | High | Not Started | High Signal (50) | api/app.py, api/auth.py, docker-compose.yml | Validate all input against an allow-list (type, length, format, range) at the boundary and reject anything that does not match. |
| 46 | Cross site scripting | Tampering | High | Not Started | High Signal (50) | api/app.py, api/auth.py, docker-compose.yml | Encode output for its context (HTML, attribute, JS, URL), validate input, and deploy a strict Content Security Policy. |
| 48 | Data flow sniffing | Information Disclosure | High | Not Started | High Signal (50) | api/app.py, api/auth.py, docker-compose.yml | Encrypt the channel (TLS 1.2+, IPsec) and do not send sensitive data that the receiver does not need. |
| 53 | Gateway may be subject to elevation of privilege using remote code execution | Elevation Of Privilege | High | Not Started | High Signal (50) | api/app.py, api/auth.py, docker-compose.yml | Remove dangerous sinks (eval, shell, unsafe deserialization), validate input, sandbox the process and run it with least privilege. |
| 56 | Cross site scripting | Tampering | High | Not Started | High Signal (50) | api/app.py, api/payments.py, docker-compose.yml | Encode output for its context (HTML, attribute, JS, URL), validate input, and deploy a strict Content Security Policy. |
| 61 | Gateway may be subject to elevation of privilege using remote code execution | Elevation Of Privilege | High | Not Started | High Signal (50) | api/app.py, api/payments.py, docker-compose.yml | Remove dangerous sinks (eval, shell, unsafe deserialization), validate input, sandbox the process and run it with least privilege. |
| 63 | Spoofing the Auth0 external entity | Spoofing | High | Not Started | High Signal (50) | api/auth.py, web/src/api.ts, api/app.py | Require Auth0 to authenticate (strong passwords plus MFA for people; client certificates, signed tokens or API keys with rotation for systems). |
| 68 | Billing API may be subject to elevation of privilege using remote code execution | Elevation Of Privilege | High | Not Started | High Signal (50) | api/auth.py, web/src/api.ts, api/app.py | Remove dangerous sinks (eval, shell, unsafe deserialization), validate input, sandbox the process and run it with least privilege. |
| 82 | Authorization bypass | Information Disclosure | High | Not Started | High Signal (50) | api/audit.py, api/app.py, api/auth.py | Check authorization server-side on every request, deny by default, and add tests for every role and resource combination. |
| 85 | Authorization bypass | Information Disclosure | High | Not Started | High Signal (50) | api/app.py, api/auth.py, docker-compose.yml | Check authorization server-side on every request, deny by default, and add tests for every role and resource combination. |
| 97 | Stored XSS via invoice memo rendered as HTML | Tampering | High | Not Started | High Signal (50) | web/src/api.ts, docker-compose.yml, web/src/InvoiceView.tsx | Render memo as text, or sanitize with DOMPurify before insertion; add a strict CSP. |

## Full threat register

Template: STRIDE Core 1.0.0 · Diagrams: 1 · Elements: 30 · Threats: 97

| State | Count |
|---|---:|
| Not Started | 92 |
| Needs Investigation | 2 |
| Not Applicable | 1 |
| Mitigation Implemented | 2 |

| ID | Category | Priority | State | Signal | Title | Interaction |
|---:|---|---|---|---|---|---|
| 1 | Spoofing | High | Not Started | High Signal | Spoofing the Billing SPA process | From Customer to Billing SPA via Browser interactions |
| 2 | Spoofing | High | Not Started | High Signal | Spoofing the Customer external entity | From Customer to Billing SPA via Browser interactions |
| 3 | Tampering | High | Not Started | High Signal | Potential lack of input validation for Billing SPA | From Customer to Billing SPA via Browser interactions |
| 4 | Repudiation | Low | Not Started | Medium Signal | Potential data repudiation by Billing SPA | From Customer to Billing SPA via Browser interactions |
| 5 | Information Disclosure | High | Not Started | High Signal | Data flow sniffing | From Customer to Billing SPA via Browser interactions |
| 6 | Denial Of Service | Medium | Not Started | Medium Signal | Potential process crash or stop for Billing SPA | From Customer to Billing SPA via Browser interactions |
| 7 | Denial Of Service | Low | Not Started | Medium Signal | Data flow Browser interactions is potentially interrupted | From Customer to Billing SPA via Browser interactions |
| 8 | Elevation Of Privilege | Medium | Not Started | Medium Signal | Elevation using impersonation | From Customer to Billing SPA via Browser interactions |
| 9 | Elevation Of Privilege | High | Not Started | High Signal | Billing SPA may be subject to elevation of privilege using remote code execution | From Customer to Billing SPA via Browser interactions |
| 10 | Elevation Of Privilege | Medium | Not Started | Medium Signal | Elevation by changing the execution flow in Billing SPA | From Customer to Billing SPA via Browser interactions |
| 11 | Spoofing | Medium | Not Started | Medium Signal | Spoofing of the Auth0 external destination entity | From Billing SPA to Auth0 via Login and token requests |
| 12 | Repudiation | Low | Not Started | Medium Signal | External entity Auth0 potentially denies receiving data | From Billing SPA to Auth0 via Login and token requests |
| 13 | Denial Of Service | Low | Not Started | Medium Signal | Data flow Login and token requests is potentially interrupted | From Billing SPA to Auth0 via Login and token requests |
| 14 | Elevation Of Privilege | High | Not Started | High Signal | Weakness in SSO authorization | From Billing SPA to Auth0 via Login and token requests |
| 15 | Spoofing | High | Not Started | High Signal | Spoofing the Billing SPA process | From Billing SPA to Gateway via API requests (Bearer JWT) |
| 16 | Tampering | Medium | Not Started | Medium Signal | JavaScript Object Notation processing | From Billing SPA to Gateway via API requests (Bearer JWT) |
| 17 | Tampering | High | Not Applicable | Generic | Cross site scripting | From Billing SPA to Gateway via API requests (Bearer JWT) |
| 18 | Repudiation | Low | Not Started | Medium Signal | Potential data repudiation by Gateway | From Billing SPA to Gateway via API requests (Bearer JWT) |
| 19 | Denial Of Service | Medium | Not Started | Medium Signal | Potential process crash or stop for Gateway | From Billing SPA to Gateway via API requests (Bearer JWT) |
| 20 | Denial Of Service | Low | Not Started | Medium Signal | Data flow API requests (Bearer JWT) is potentially interrupted | From Billing SPA to Gateway via API requests (Bearer JWT) |
| 21 | Elevation Of Privilege | Medium | Not Started | Medium Signal | Elevation using impersonation | From Billing SPA to Gateway via API requests (Bearer JWT) |
| 22 | Elevation Of Privilege | High | Not Started | High Signal | Gateway may be subject to elevation of privilege using remote code execution | From Billing SPA to Gateway via API requests (Bearer JWT) |
| 23 | Elevation Of Privilege | Medium | Not Started | Medium Signal | Elevation by changing the execution flow in Gateway | From Billing SPA to Gateway via API requests (Bearer JWT) |
| 24 | Spoofing | High | Not Started | High Signal | Spoofing the Gateway process | From Gateway to Billing SPA via API responses |
| 25 | Tampering | Medium | Not Started | Medium Signal | Gateway process memory tampered | From Gateway to Billing SPA via API responses |
| 26 | Tampering | Medium | Not Started | Medium Signal | JavaScript Object Notation processing | From Gateway to Billing SPA via API responses |
| 27 | Repudiation | Low | Not Started | Medium Signal | Potential data repudiation by Billing SPA | From Gateway to Billing SPA via API responses |
| 28 | Denial Of Service | Medium | Not Started | Medium Signal | Potential process crash or stop for Billing SPA | From Gateway to Billing SPA via API responses |
| 29 | Denial Of Service | Low | Not Started | Medium Signal | Data flow API responses is potentially interrupted | From Gateway to Billing SPA via API responses |
| 30 | Elevation Of Privilege | Medium | Not Started | Medium Signal | Elevation using impersonation | From Gateway to Billing SPA via API responses |
| 31 | Elevation Of Privilege | High | Not Started | High Signal | Billing SPA may be subject to elevation of privilege using remote code execution | From Gateway to Billing SPA via API responses |
| 32 | Elevation Of Privilege | Medium | Not Started | Medium Signal | Elevation by changing the execution flow in Billing SPA | From Gateway to Billing SPA via API responses |
| 33 | Spoofing | High | Not Started | High Signal | Spoofing the Gateway process | From Gateway to Billing API via Proxied API requests |
| 34 | Spoofing | High | Mitigation Implemented | Medium Signal | Spoofing the Billing API process | From Gateway to Billing API via Proxied API requests |
| 35 | Tampering | High | Not Started | High Signal | Potential lack of input validation for Billing API | From Gateway to Billing API via Proxied API requests |
| 36 | Tampering | Medium | Not Started | Medium Signal | Gateway process memory tampered | From Gateway to Billing API via Proxied API requests |
| 37 | Repudiation | Low | Not Started | Medium Signal | Potential data repudiation by Billing API | From Gateway to Billing API via Proxied API requests |
| 38 | Information Disclosure | High | Needs Investigation | Medium Signal | Data flow sniffing | From Gateway to Billing API via Proxied API requests |
| 39 | Denial Of Service | Medium | Not Started | Medium Signal | Potential process crash or stop for Billing API | From Gateway to Billing API via Proxied API requests |
| 40 | Denial Of Service | Low | Not Started | Medium Signal | Data flow Proxied API requests is potentially interrupted | From Gateway to Billing API via Proxied API requests |
| 41 | Elevation Of Privilege | Medium | Not Started | Medium Signal | Elevation using impersonation | From Gateway to Billing API via Proxied API requests |
| 42 | Elevation Of Privilege | High | Not Started | High Signal | Billing API may be subject to elevation of privilege using remote code execution | From Gateway to Billing API via Proxied API requests |
| 43 | Elevation Of Privilege | Medium | Not Started | Medium Signal | Elevation by changing the execution flow in Billing API | From Gateway to Billing API via Proxied API requests |
| 44 | Spoofing | High | Not Started | High Signal | Spoofing the Gateway process | From Billing API to Gateway via Proxied API responses |
| 45 | Tampering | High | Not Started | High Signal | Potential lack of input validation for Gateway | From Billing API to Gateway via Proxied API responses |
| 46 | Tampering | High | Not Started | High Signal | Cross site scripting | From Billing API to Gateway via Proxied API responses |
| 47 | Repudiation | Low | Not Started | Medium Signal | Potential data repudiation by Gateway | From Billing API to Gateway via Proxied API responses |
| 48 | Information Disclosure | High | Not Started | High Signal | Data flow sniffing | From Billing API to Gateway via Proxied API responses |
| 49 | Information Disclosure | Medium | Not Started | Medium Signal | Weak authentication scheme | From Billing API to Gateway via Proxied API responses |
| 50 | Denial Of Service | Medium | Not Started | Medium Signal | Potential process crash or stop for Gateway | From Billing API to Gateway via Proxied API responses |
| 51 | Denial Of Service | Low | Not Started | Medium Signal | Data flow Proxied API responses is potentially interrupted | From Billing API to Gateway via Proxied API responses |
| 52 | Elevation Of Privilege | Medium | Not Started | Medium Signal | Elevation using impersonation | From Billing API to Gateway via Proxied API responses |
| 53 | Elevation Of Privilege | High | Not Started | High Signal | Gateway may be subject to elevation of privilege using remote code execution | From Billing API to Gateway via Proxied API responses |
| 54 | Elevation Of Privilege | Medium | Not Started | Medium Signal | Elevation by changing the execution flow in Gateway | From Billing API to Gateway via Proxied API responses |
| 55 | Tampering | Medium | Not Started | Medium Signal | JavaScript Object Notation processing | From Stripe to Gateway via Payment webhooks |
| 56 | Tampering | High | Not Started | High Signal | Cross site scripting | From Stripe to Gateway via Payment webhooks |
| 57 | Repudiation | Low | Not Started | Medium Signal | Potential data repudiation by Gateway | From Stripe to Gateway via Payment webhooks |
| 58 | Denial Of Service | Medium | Not Started | Medium Signal | Potential process crash or stop for Gateway | From Stripe to Gateway via Payment webhooks |
| 59 | Denial Of Service | Low | Not Started | Medium Signal | Data flow Payment webhooks is potentially interrupted | From Stripe to Gateway via Payment webhooks |
| 60 | Elevation Of Privilege | Medium | Not Started | Medium Signal | Elevation using impersonation | From Stripe to Gateway via Payment webhooks |
| 61 | Elevation Of Privilege | High | Not Started | High Signal | Gateway may be subject to elevation of privilege using remote code execution | From Stripe to Gateway via Payment webhooks |
| 62 | Elevation Of Privilege | Medium | Not Started | Medium Signal | Elevation by changing the execution flow in Gateway | From Stripe to Gateway via Payment webhooks |
| 63 | Spoofing | High | Not Started | High Signal | Spoofing the Auth0 external entity | From Auth0 to Billing API via JWKS fetch |
| 64 | Repudiation | Low | Not Started | Medium Signal | Potential data repudiation by Billing API | From Auth0 to Billing API via JWKS fetch |
| 65 | Denial Of Service | Medium | Not Started | Medium Signal | Potential process crash or stop for Billing API | From Auth0 to Billing API via JWKS fetch |
| 66 | Denial Of Service | Low | Not Started | Medium Signal | Data flow JWKS fetch is potentially interrupted | From Auth0 to Billing API via JWKS fetch |
| 67 | Elevation Of Privilege | Medium | Not Started | Medium Signal | Elevation using impersonation | From Auth0 to Billing API via JWKS fetch |
| 68 | Elevation Of Privilege | High | Not Started | High Signal | Billing API may be subject to elevation of privilege using remote code execution | From Auth0 to Billing API via JWKS fetch |
| 69 | Elevation Of Privilege | Medium | Not Started | Medium Signal | Elevation by changing the execution flow in Billing API | From Auth0 to Billing API via JWKS fetch |
| 70 | Spoofing | Medium | Not Started | Medium Signal | Spoofing of destination data store Invoices DB | From Billing API to Invoices DB via Invoice queries |
| 71 | Tampering | High | Mitigation Implemented | Medium Signal | Potential SQL injection vulnerability for Invoices DB | From Billing API to Invoices DB via Invoice queries |
| 72 | Information Disclosure | High | Needs Investigation | Medium Signal | Authorization bypass | From Billing API to Invoices DB via Invoice queries |
| 73 | Denial Of Service | Medium | Not Started | Medium Signal | Potential excessive resource consumption for Billing API or Invoices DB | From Billing API to Invoices DB via Invoice queries |
| 74 | Spoofing | Medium | Not Started | Medium Signal | Spoofing of source data store Invoices DB | From Invoices DB to Billing API via Invoice rows |
| 75 | Information Disclosure | Medium | Not Started | Medium Signal | Weak access control for a resource | From Invoices DB to Billing API via Invoice rows |
| 76 | Spoofing | Medium | Not Started | Medium Signal | Spoofing of destination data store Audit log | From Billing API to Audit log via Audit events |
| 77 | Tampering | Medium | Not Started | Medium Signal | Risks from logging | From Billing API to Audit log via Audit events |
| 78 | Repudiation | Medium | Not Started | Medium Signal | Lower trusted subject updates logs | From Billing API to Audit log via Audit events |
| 79 | Repudiation | Low | Not Started | Medium Signal | Data logs from an unknown source | From Billing API to Audit log via Audit events |
| 80 | Repudiation | Medium | Not Started | Medium Signal | Insufficient auditing | From Billing API to Audit log via Audit events |
| 81 | Repudiation | Medium | Not Started | Medium Signal | Potential weak protections for audit data | From Billing API to Audit log via Audit events |
| 82 | Information Disclosure | High | Not Started | High Signal | Authorization bypass | From Billing API to Audit log via Audit events |
| 83 | Denial Of Service | Medium | Not Started | Medium Signal | Potential excessive resource consumption for Billing API or Audit log | From Billing API to Audit log via Audit events |
| 84 | Spoofing | Medium | Not Started | Medium Signal | Spoofing of destination data store Job queue | From Billing API to Job queue via Receipt jobs |
| 85 | Information Disclosure | High | Not Started | High Signal | Authorization bypass | From Billing API to Job queue via Receipt jobs |
| 86 | Denial Of Service | Medium | Not Started | Medium Signal | Potential excessive resource consumption for Billing API or Job queue | From Billing API to Job queue via Receipt jobs |
| 87 | Spoofing | Medium | Not Started | Medium Signal | Spoofing of source data store Job queue | From Job queue to Receipt worker via Receipt jobs pulled |
| 88 | Information Disclosure | Medium | Not Started | Medium Signal | Weak access control for a resource | From Job queue to Receipt worker via Receipt jobs pulled |
| 89 | Spoofing | Medium | Not Started | Medium Signal | Spoofing of source data store Invoices DB | From Invoices DB to Receipt worker via Invoice data |
| 90 | Information Disclosure | Medium | Not Started | Medium Signal | Weak access control for a resource | From Invoices DB to Receipt worker via Invoice data |
| 91 | Spoofing | Medium | Not Started | Medium Signal | Spoofing of the Stripe external destination entity | From Billing API to Stripe via Payment intents |
| 92 | Repudiation | Low | Not Started | Medium Signal | External entity Stripe potentially denies receiving data | From Billing API to Stripe via Payment intents |
| 93 | Denial Of Service | Low | Not Started | Medium Signal | Data flow Payment intents is potentially interrupted | From Billing API to Stripe via Payment intents |
| 94 | Spoofing | Medium | Not Started | Medium Signal | Spoofing of the SendGrid external destination entity | From Receipt worker to SendGrid via Receipt emails |
| 95 | Repudiation | Low | Not Started | Medium Signal | External entity SendGrid potentially denies receiving data | From Receipt worker to SendGrid via Receipt emails |
| 96 | Denial Of Service | Low | Not Started | Medium Signal | Data flow Receipt emails is potentially interrupted | From Receipt worker to SendGrid via Receipt emails |
| 97 | Tampering | High | Not Started | High Signal | Stored XSS via invoice memo rendered as HTML | From Gateway to Billing SPA via API responses |
