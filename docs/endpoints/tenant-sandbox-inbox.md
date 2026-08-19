# Sandbox Inbox & Delivery Verification (`/v1/tenant/sandbox/...`, `/v1/tenant/delivery/verify`)

> **Last Verified**: `2026-08-19` — verified against `internal/sandbox` unit tests and `test/sandbox_test.go`.

## Overview

In the **test environment the engine does not send email or SMS**. Every message it would have sent is stored instead, and read back through an inbox API with its verification link and one-time code intact.

That is what makes a test environment usable. A signup, a magic link, a password reset or an SMS second factor runs end to end, the rendered message is inspected, and the credential inside it is used — without delivering to a real inbox, paying a carrier per code, or having a handset in somebody's hand to read the digits off.

**In the live environment nothing changes.** Messages are delivered by the configured provider exactly as before.

---

## The Two Endpoints Answer Different Questions

| You want to know | Use |
| :--- | :--- |
| Did the engine produce the right message, with the right code and link in it? | The **inbox** — no provider is involved |
| Do the SMTP or Twilio credentials in my configuration actually work? | **Delivery verification** — nothing captured can answer this |

Neither substitutes for the other. A thousand captured messages say nothing about whether your provider accepts mail, and one successful delivery test says nothing about whether your 2FA template renders a code.

---

## What Gets Captured

Interception happens at the provider interface, not at each place the engine decides to send. So every message the engine sends is covered — including message types added after this was written.

Recognised templates, from the subject line:

| `template` | Sent when |
| :--- | :--- |
| `email_verification` | A new account needs its address confirmed |
| `magic_link` | Passwordless sign-in was requested |
| `two_factor_code` | A second-factor code went out over email or SMS |
| `impersonation_notice` | An administrator started impersonating the user |
| `email_change` | A change of address needs confirming at the new one |
| `recovery_email_verification` | A recovery address was added |

An unrecognised subject stores an empty `template` rather than a guess. This field exists so a test can assert *which* message was triggered, and a wrong answer would defeat that more thoroughly than an absent one.

---

## Listing The Inbox (`GET /v1/tenant/sandbox/messages`)

*Requires a **test** secret key `sk_test_...` or a console admin JWT.*

```bash
curl "https://api.authn.com/v1/tenant/sandbox/messages?recipient=ada@example.test" \
  -H "Authorization: Bearer sk_test_..."
```

| Query parameter | Meaning |
| :--- | :--- |
| `recipient` | Exact email address or E.164 number |
| `channel` | `email` or `sms` |
| `limit` | Page size, default `50`, capped at `200` |
| `offset` | How many of the newest messages to skip |

* **Response (`200 OK`)**:
```json
{
  "environment": "test",
  "total": 2,
  "messages": [
    {
      "id": "sbxmsg_2f9c1a7b4e0d",
      "channel": "email",
      "environment": "test",
      "recipient": "ada@example.test",
      "subject": "Verify your email address",
      "template": "email_verification",
      "code": "",
      "metadata": {
        "link": "https://api.authn.com/v1/client/auth/verify-email?token=32b3c1b7a1695dbb",
        "text_body": "Welcome to Acme! Please verify your email address..."
      },
      "created_at": "2026-08-19T11:04:22Z"
    }
  ]
}
```

**Messages come back newest first**, so `messages[0]` is what the flow you just triggered produced.

**`body` is absent from the listing.** A rendered HTML email is tens of times larger than the fields anyone pages through an inbox for, and the two values a test actually reads — `code` and `metadata.link` — are present either way. Ask for a single message when you want the document.

**`total` counts every message matching the filter, before paging.** A test polling for a message cannot learn that from the page length, which is why it is reported separately.

**`code` and `metadata.link` are extracted at capture time**, so completing a flow does not mean parsing rendered HTML. The rendering is styling and changes freely; these two are the contract. A message carrying no code stores `""` rather than guessing, and the extraction is deliberately strict — a loose match is worse than no match, because a test reading a wrong value fails in a way that looks like the engine generated the wrong credential.

---

## Reading One Message (`GET /v1/tenant/sandbox/messages/:id`)

Same as a listing entry, plus `body` — the message exactly as the provider would have received it.

* **Response (`200 OK`)**:
```json
{
  "environment": "test",
  "message": {
    "id": "sbxmsg_2f9c1a7b4e0d",
    "channel": "email",
    "environment": "test",
    "recipient": "ada@example.test",
    "subject": "Verify your email address",
    "template": "email_verification",
    "code": "",
    "metadata": { "link": "https://api.authn.com/v1/client/auth/verify-email?token=32b3c1b7a1695dbb" },
    "created_at": "2026-08-19T11:04:22Z",
    "body": "<!DOCTYPE html><html>...</html>"
  }
}
```

* **Response (`404 Not Found`)** — no such message, **or** it belongs to another tenant. The two are deliberately indistinguishable: telling you the ID exists somewhere is itself the disclosure.

---

## Emptying The Inbox (`DELETE /v1/tenant/sandbox/messages`)

```bash
curl -X DELETE https://api.authn.com/v1/tenant/sandbox/messages \
  -H "Authorization: Bearer sk_test_..."
```

* **Response (`200 OK`)**:
```json
{
  "message": "sandbox inbox emptied",
  "environment": "test",
  "removed": 12
}
```

Deletes only the calling tenant's `test` messages. Run it between test runs so an assertion on "the newest message" is not answered by the previous run's captures.

---

## The Inbox Refuses A Live Key

* **Response (`403 Forbidden`)** — on all three inbox routes, given a valid `sk_live_...` key:
```json
{
  "error": "the sandbox inbox exists only in the test environment; this credential addresses live",
  "code": "forbidden"
}
```

This is a refusal rather than an empty list, and the difference matters. Nothing is ever captured outside test, so an empty list would be a *true* answer to the wrong question — and **"my message is missing"** is a far worse thing to leave an operator concluding than **"you are looking at the wrong environment"**.

---

## Verifying Real Delivery (`POST /v1/tenant/delivery/verify`)

*Requires a **console admin JWT**. A secret key is refused — see below.*

Sends **one real message** through the configured provider, bypassing the sandbox. That bypass is the entire point: a captured message never reaches a provider, so no amount of sandbox traffic establishes that the credentials in your configuration work. Sending is the only test of a send.

```bash
curl -X POST https://api.authn.com/v1/tenant/delivery/verify \
  -H "Authorization: Bearer eyJ..." \
  -H "Content-Type: application/json" \
  -d '{"channel": "email"}'
```

* **Request** — `channel` is `email` or `sms`. **There is no `recipient` field.**
* **Response (`200 OK`)**:
```json
{
  "message": "delivery test accepted by the provider",
  "channel": "email",
  "recipient": "operator@acme.com",
  "driver": "ses"
}
```

`driver` names the backend that answered, so you can see which one handled it rather than inferring it from configuration you may not be looking at.

### The recipient is you, and cannot be anything else

The address is the **signed-in operator's own**, read from their account. There is no field to supply one, so this endpoint cannot be aimed at a third party by construction rather than by validation — and a check of whether a provider accepts mail does not need a choice of target to answer.

That is also why a **secret key is refused**:

* **Response (`403 Forbidden`)**:
```json
{
  "error": "delivery verification requires a console session: it sends to the signed-in operator's own address, and a secret key has none",
  "code": "forbidden"
}
```

A secret key identifies an application, not a person. There is no address behind it that the engine has seen anybody prove control of.

### Other responses

| Status | Code | Meaning |
| :--- | :--- | :--- |
| `400` | `validation_failed` | `channel` is neither `email` nor `sms` |
| `403` | `email_verification_required` | Verify your own address before using it to test delivery |
| `403` | `forbidden` | Channel `sms` with no verified phone number on your account |
| `404` | `not_found` | The signed-in operator's account could not be read in this environment |
| `429` | `rate_limited` | More than 3 verifications per window for this tenant and channel |
| `502` | `service_unavailable` | The provider rejected the message; its own error is in the body |
| `503` | `service_unavailable` | No provider is configured for that channel |

A `502` carries the provider's own words — `the email provider rejected the message: 535 authentication failed` — because that string is the answer you came for.

The `429` limit is low on purpose. The endpoint sends to your own address through your own provider account, so the second message tells you exactly what the first one did. The cap bounds a misconfigured retry loop, not an abuse: anybody able to call this already holds the provider credentials it uses.

---

## Captures Expire

Captured bodies hold verification links and one-time codes **in plain text** — a test harness has to read them, so that is the point of the store rather than an oversight. It is also why the retention window is short.

`SANDBOX_MESSAGE_RETENTION` (default `24h`) is swept by the background retention job. A test reads its message within seconds of triggering it; everything kept past that is an archive of credentials that still work.

Do not treat the inbox as a log. It is a mailbox with a short lease.

---

## A Typical Test Run

1. `DELETE /v1/tenant/sandbox/messages` — start from empty.
2. `POST /v1/client/auth/signup` with `pk_test_...`.
3. `GET /v1/tenant/sandbox/messages?recipient=...` — assert `total` is 1 and `template` is `email_verification`.
4. Pull the token out of `metadata.link` and `GET /v1/client/auth/verify-email?token=...`.
5. Separately, once, after configuring SMTP: `POST /v1/tenant/delivery/verify` and check your own inbox.

Step 5 is the one that catches a wrong SMTP password. Steps 1–4 never would, and would keep passing while every live message bounced.
