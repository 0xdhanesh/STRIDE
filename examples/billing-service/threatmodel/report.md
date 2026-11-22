# Billing service

Template: STRIDE Core 1.0.0 · Diagrams: 1 · Elements: 30 · Threats: 97

| State | Count |
|---|---:|
| Not Started | 92 |
| Needs Investigation | 2 |
| Not Applicable | 1 |
| Mitigation Implemented | 2 |

| ID | Category | Priority | State | Title | Interaction |
|---:|---|---|---|---|---|
| 1 | Spoofing | High | Not Started | Spoofing the Billing SPA process | From Customer to Billing SPA via Browser interactions |
| 2 | Spoofing | High | Not Started | Spoofing the Customer external entity | From Customer to Billing SPA via Browser interactions |
| 3 | Tampering | High | Not Started | Potential lack of input validation for Billing SPA | From Customer to Billing SPA via Browser interactions |
| 4 | Repudiation | Low | Not Started | Potential data repudiation by Billing SPA | From Customer to Billing SPA via Browser interactions |
| 5 | Information Disclosure | High | Not Started | Data flow sniffing | From Customer to Billing SPA via Browser interactions |
| 6 | Denial Of Service | Medium | Not Started | Potential process crash or stop for Billing SPA | From Customer to Billing SPA via Browser interactions |
| 7 | Denial Of Service | Low | Not Started | Data flow Browser interactions is potentially interrupted | From Customer to Billing SPA via Browser interactions |
| 8 | Elevation Of Privilege | Medium | Not Started | Elevation using impersonation | From Customer to Billing SPA via Browser interactions |
| 9 | Elevation Of Privilege | High | Not Started | Billing SPA may be subject to elevation of privilege using remote code execution | From Customer to Billing SPA via Browser interactions |
| 10 | Elevation Of Privilege | Medium | Not Started | Elevation by changing the execution flow in Billing SPA | From Customer to Billing SPA via Browser interactions |
| 11 | Spoofing | Medium | Not Started | Spoofing of the Auth0 external destination entity | From Billing SPA to Auth0 via Login and token requests |
| 12 | Repudiation | Low | Not Started | External entity Auth0 potentially denies receiving data | From Billing SPA to Auth0 via Login and token requests |
| 13 | Denial Of Service | Low | Not Started | Data flow Login and token requests is potentially interrupted | From Billing SPA to Auth0 via Login and token requests |
| 14 | Elevation Of Privilege | High | Not Started | Weakness in SSO authorization | From Billing SPA to Auth0 via Login and token requests |
| 15 | Spoofing | High | Not Started | Spoofing the Billing SPA process | From Billing SPA to Gateway via API requests (Bearer JWT) |
| 16 | Tampering | Medium | Not Started | JavaScript Object Notation processing | From Billing SPA to Gateway via API requests (Bearer JWT) |
| 17 | Tampering | High | Not Applicable | Cross site scripting | From Billing SPA to Gateway via API requests (Bearer JWT) |
| 18 | Repudiation | Low | Not Started | Potential data repudiation by Gateway | From Billing SPA to Gateway via API requests (Bearer JWT) |
| 19 | Denial Of Service | Medium | Not Started | Potential process crash or stop for Gateway | From Billing SPA to Gateway via API requests (Bearer JWT) |
| 20 | Denial Of Service | Low | Not Started | Data flow API requests (Bearer JWT) is potentially interrupted | From Billing SPA to Gateway via API requests (Bearer JWT) |
| 21 | Elevation Of Privilege | Medium | Not Started | Elevation using impersonation | From Billing SPA to Gateway via API requests (Bearer JWT) |
| 22 | Elevation Of Privilege | High | Not Started | Gateway may be subject to elevation of privilege using remote code execution | From Billing SPA to Gateway via API requests (Bearer JWT) |
| 23 | Elevation Of Privilege | Medium | Not Started | Elevation by changing the execution flow in Gateway | From Billing SPA to Gateway via API requests (Bearer JWT) |
| 24 | Spoofing | High | Not Started | Spoofing the Gateway process | From Gateway to Billing SPA via API responses |
| 25 | Tampering | Medium | Not Started | Gateway process memory tampered | From Gateway to Billing SPA via API responses |
| 26 | Tampering | Medium | Not Started | JavaScript Object Notation processing | From Gateway to Billing SPA via API responses |
| 27 | Repudiation | Low | Not Started | Potential data repudiation by Billing SPA | From Gateway to Billing SPA via API responses |
| 28 | Denial Of Service | Medium | Not Started | Potential process crash or stop for Billing SPA | From Gateway to Billing SPA via API responses |
| 29 | Denial Of Service | Low | Not Started | Data flow API responses is potentially interrupted | From Gateway to Billing SPA via API responses |
| 30 | Elevation Of Privilege | Medium | Not Started | Elevation using impersonation | From Gateway to Billing SPA via API responses |
| 31 | Elevation Of Privilege | High | Not Started | Billing SPA may be subject to elevation of privilege using remote code execution | From Gateway to Billing SPA via API responses |
| 32 | Elevation Of Privilege | Medium | Not Started | Elevation by changing the execution flow in Billing SPA | From Gateway to Billing SPA via API responses |
| 33 | Spoofing | High | Not Started | Spoofing the Gateway process | From Gateway to Billing API via Proxied API requests |
| 34 | Spoofing | High | Mitigation Implemented | Spoofing the Billing API process | From Gateway to Billing API via Proxied API requests |
| 35 | Tampering | High | Not Started | Potential lack of input validation for Billing API | From Gateway to Billing API via Proxied API requests |
| 36 | Tampering | Medium | Not Started | Gateway process memory tampered | From Gateway to Billing API via Proxied API requests |
| 37 | Repudiation | Low | Not Started | Potential data repudiation by Billing API | From Gateway to Billing API via Proxied API requests |
| 38 | Information Disclosure | High | Needs Investigation | Data flow sniffing | From Gateway to Billing API via Proxied API requests |
| 39 | Denial Of Service | Medium | Not Started | Potential process crash or stop for Billing API | From Gateway to Billing API via Proxied API requests |
| 40 | Denial Of Service | Low | Not Started | Data flow Proxied API requests is potentially interrupted | From Gateway to Billing API via Proxied API requests |
| 41 | Elevation Of Privilege | Medium | Not Started | Elevation using impersonation | From Gateway to Billing API via Proxied API requests |
| 42 | Elevation Of Privilege | High | Not Started | Billing API may be subject to elevation of privilege using remote code execution | From Gateway to Billing API via Proxied API requests |
| 43 | Elevation Of Privilege | Medium | Not Started | Elevation by changing the execution flow in Billing API | From Gateway to Billing API via Proxied API requests |
| 44 | Spoofing | High | Not Started | Spoofing the Gateway process | From Billing API to Gateway via Proxied API responses |
| 45 | Tampering | High | Not Started | Potential lack of input validation for Gateway | From Billing API to Gateway via Proxied API responses |
| 46 | Tampering | High | Not Started | Cross site scripting | From Billing API to Gateway via Proxied API responses |
| 47 | Repudiation | Low | Not Started | Potential data repudiation by Gateway | From Billing API to Gateway via Proxied API responses |
| 48 | Information Disclosure | High | Not Started | Data flow sniffing | From Billing API to Gateway via Proxied API responses |
| 49 | Information Disclosure | Medium | Not Started | Weak authentication scheme | From Billing API to Gateway via Proxied API responses |
| 50 | Denial Of Service | Medium | Not Started | Potential process crash or stop for Gateway | From Billing API to Gateway via Proxied API responses |
| 51 | Denial Of Service | Low | Not Started | Data flow Proxied API responses is potentially interrupted | From Billing API to Gateway via Proxied API responses |
| 52 | Elevation Of Privilege | Medium | Not Started | Elevation using impersonation | From Billing API to Gateway via Proxied API responses |
| 53 | Elevation Of Privilege | High | Not Started | Gateway may be subject to elevation of privilege using remote code execution | From Billing API to Gateway via Proxied API responses |
| 54 | Elevation Of Privilege | Medium | Not Started | Elevation by changing the execution flow in Gateway | From Billing API to Gateway via Proxied API responses |
| 55 | Tampering | Medium | Not Started | JavaScript Object Notation processing | From Stripe to Gateway via Payment webhooks |
| 56 | Tampering | High | Not Started | Cross site scripting | From Stripe to Gateway via Payment webhooks |
| 57 | Repudiation | Low | Not Started | Potential data repudiation by Gateway | From Stripe to Gateway via Payment webhooks |
| 58 | Denial Of Service | Medium | Not Started | Potential process crash or stop for Gateway | From Stripe to Gateway via Payment webhooks |
| 59 | Denial Of Service | Low | Not Started | Data flow Payment webhooks is potentially interrupted | From Stripe to Gateway via Payment webhooks |
| 60 | Elevation Of Privilege | Medium | Not Started | Elevation using impersonation | From Stripe to Gateway via Payment webhooks |
| 61 | Elevation Of Privilege | High | Not Started | Gateway may be subject to elevation of privilege using remote code execution | From Stripe to Gateway via Payment webhooks |
| 62 | Elevation Of Privilege | Medium | Not Started | Elevation by changing the execution flow in Gateway | From Stripe to Gateway via Payment webhooks |
| 63 | Spoofing | High | Not Started | Spoofing the Auth0 external entity | From Auth0 to Billing API via JWKS fetch |
| 64 | Repudiation | Low | Not Started | Potential data repudiation by Billing API | From Auth0 to Billing API via JWKS fetch |
| 65 | Denial Of Service | Medium | Not Started | Potential process crash or stop for Billing API | From Auth0 to Billing API via JWKS fetch |
| 66 | Denial Of Service | Low | Not Started | Data flow JWKS fetch is potentially interrupted | From Auth0 to Billing API via JWKS fetch |
| 67 | Elevation Of Privilege | Medium | Not Started | Elevation using impersonation | From Auth0 to Billing API via JWKS fetch |
| 68 | Elevation Of Privilege | High | Not Started | Billing API may be subject to elevation of privilege using remote code execution | From Auth0 to Billing API via JWKS fetch |
| 69 | Elevation Of Privilege | Medium | Not Started | Elevation by changing the execution flow in Billing API | From Auth0 to Billing API via JWKS fetch |
| 70 | Spoofing | Medium | Not Started | Spoofing of destination data store Invoices DB | From Billing API to Invoices DB via Invoice queries |
| 71 | Tampering | High | Mitigation Implemented | Potential SQL injection vulnerability for Invoices DB | From Billing API to Invoices DB via Invoice queries |
| 72 | Information Disclosure | High | Needs Investigation | Authorization bypass | From Billing API to Invoices DB via Invoice queries |
| 73 | Denial Of Service | Medium | Not Started | Potential excessive resource consumption for Billing API or Invoices DB | From Billing API to Invoices DB via Invoice queries |
| 74 | Spoofing | Medium | Not Started | Spoofing of source data store Invoices DB | From Invoices DB to Billing API via Invoice rows |
| 75 | Information Disclosure | Medium | Not Started | Weak access control for a resource | From Invoices DB to Billing API via Invoice rows |
| 76 | Spoofing | Medium | Not Started | Spoofing of destination data store Audit log | From Billing API to Audit log via Audit events |
| 77 | Tampering | Medium | Not Started | Risks from logging | From Billing API to Audit log via Audit events |
| 78 | Repudiation | Medium | Not Started | Lower trusted subject updates logs | From Billing API to Audit log via Audit events |
| 79 | Repudiation | Low | Not Started | Data logs from an unknown source | From Billing API to Audit log via Audit events |
| 80 | Repudiation | Medium | Not Started | Insufficient auditing | From Billing API to Audit log via Audit events |
| 81 | Repudiation | Medium | Not Started | Potential weak protections for audit data | From Billing API to Audit log via Audit events |
| 82 | Information Disclosure | High | Not Started | Authorization bypass | From Billing API to Audit log via Audit events |
| 83 | Denial Of Service | Medium | Not Started | Potential excessive resource consumption for Billing API or Audit log | From Billing API to Audit log via Audit events |
| 84 | Spoofing | Medium | Not Started | Spoofing of destination data store Job queue | From Billing API to Job queue via Receipt jobs |
| 85 | Information Disclosure | High | Not Started | Authorization bypass | From Billing API to Job queue via Receipt jobs |
| 86 | Denial Of Service | Medium | Not Started | Potential excessive resource consumption for Billing API or Job queue | From Billing API to Job queue via Receipt jobs |
| 87 | Spoofing | Medium | Not Started | Spoofing of source data store Job queue | From Job queue to Receipt worker via Receipt jobs pulled |
| 88 | Information Disclosure | Medium | Not Started | Weak access control for a resource | From Job queue to Receipt worker via Receipt jobs pulled |
| 89 | Spoofing | Medium | Not Started | Spoofing of source data store Invoices DB | From Invoices DB to Receipt worker via Invoice data |
| 90 | Information Disclosure | Medium | Not Started | Weak access control for a resource | From Invoices DB to Receipt worker via Invoice data |
| 91 | Spoofing | Medium | Not Started | Spoofing of the Stripe external destination entity | From Billing API to Stripe via Payment intents |
| 92 | Repudiation | Low | Not Started | External entity Stripe potentially denies receiving data | From Billing API to Stripe via Payment intents |
| 93 | Denial Of Service | Low | Not Started | Data flow Payment intents is potentially interrupted | From Billing API to Stripe via Payment intents |
| 94 | Spoofing | Medium | Not Started | Spoofing of the SendGrid external destination entity | From Receipt worker to SendGrid via Receipt emails |
| 95 | Repudiation | Low | Not Started | External entity SendGrid potentially denies receiving data | From Receipt worker to SendGrid via Receipt emails |
| 96 | Denial Of Service | Low | Not Started | Data flow Receipt emails is potentially interrupted | From Receipt worker to SendGrid via Receipt emails |
| 97 | Tampering | High | Not Started | Stored XSS via invoice memo rendered as HTML | From Gateway to Billing SPA via API responses |
