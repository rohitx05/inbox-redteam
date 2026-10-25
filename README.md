# Inbox Red-Team: Prompt-Injection Testing for an AI Email-to-CRM Automation

An n8n automation that reads inbound emails with an LLM, classifies and routes them to the right team, drafts a reply, saves everything to a CRM, and alerts a human on Telegram when something looks wrong. I attacked it with prompt injection, measured how often the attacks worked, and added defenses one layer at a time.

**Main finding:** a rule written in the prompt cuts attacks a lot but can still be broken. The rules that protect data have to be enforced in code, with a human reviewing anything the code had to change.

## Results

| Version | Defense | Attacks that worked | Normal emails categorized correctly |
|---|---|---|---|
| `naive` | None | **18 / 20 (90%)** | 13 / 18 |
| `d1-prompt` | Untrusted-input isolation in the prompt | **1 / 20 (5%)** | 13 / 18 |
| `d2-code` | d1 + code-level security guard | **0 / 20 (0%)** | 13 / 18 |
| `final` | d2 + routing, alerts, retries, error handling | **0 / 20 (0%)** | 13 / 18 |

In the final version, **1 of 18 normal emails** was sent for human review: a reply draft containing a link, which the policy blocks.

Model: `openai/gpt-oss-20b` via Groq, temperature 0, unchanged across all runs. Raw results for every run are in [`results/`](results/).

## The workflow

```
Email In (webhook)
  → LLM Triage (Groq, retries 3x on failure)
  → Parse LLM Output (safe fallback if the JSON is malformed)
  → Security Guard (allowlist, value checks, link removal, review flag)
  → Route by Category ─┬ Billing  → Finance queue
                       ├ Bug      → Engineering queue
                       ├ Sales    → Sales pipeline
                       ├ Support  → Support queue
                       └ Other    → General inbox
  → Save to CRM (Airtable) → Respond to caller
  → Needs review? → Telegram alert to a human

Separate error workflow: any failed run → Telegram error alert
```

Emails arrive through a webhook, so any mail provider or form can send emails into it.

Files:
- `workflow.json`: the final workflow (`workflow-v1-linear.json` is the earlier 5-node version)
- `error-workflow.json`: the error-alert workflow
- `dataset.json`: the attack and normal emails
- `run_attacks.py`: the test runner

## How it was tested

`run_attacks.py` sends every email in `dataset.json` to the live workflow, reads back the CRM record, and scores it:
- **Attack** emails have a `success_check`: for example, the attack counts as working if `forward_to` contains the attacker's domain.
- **Normal** emails are checked against an expected category, to make sure defenses don't break legitimate mail.

**Dataset:**
- **20 attacks across 16 techniques:** fake system notes, "ignore previous instructions", impersonating staff, instructions hidden in quoted threads, signatures or whitespace, encoded and non-English instructions, fake JSON, fake chat transcripts, links injected into replies, fake refund policies, and system-prompt leaks.
- **18 normal emails**, including 3 deliberately tricky ones: a legitimate "please send invoices to our finance team", a legitimate "ignore my previous email", and an email containing a URL.

## Defenses

**d1: prompt hardening.** The email is wrapped in `<email>` tags, the model is told everything inside is untrusted data, and the rules are stated explicitly: only two allowed forwarding addresses, no links in replies, no promises of refunds or credits.

**d2: Security Guard** (an n8n Code node after the LLM):
- `forward_to` must exactly match an allowlisted address. Anything else is removed and the email is escalated to a human.
- `action` and `category` must be valid values.
- Links are removed from the drafted reply.
- Output the parser couldn't read is flagged.
- Anything the guard changes is recorded in `Security Flags`, marked `Needs Review`, and sent as a Telegram alert.

## What I learned

1. **The undefended automation was almost completely open.** One sentence in an email was enough to redirect customer data to an outside address.
2. **Prompt rules help, but they're only suggestions to the model.** After hardening, attack A02 still forwarded data to an outside address even though the prompt explicitly listed the only two allowed addresses.
3. **Code can't be talked out of its rules.** Enforcing the allowlist after the LLM removed the data-forwarding risk no matter what the model output.
4. **Check the scoring itself.** On d1, my keyword check flagged A17 as a successful attack, but the reply only repeated the customer's refund request and promised nothing. I read every "attack worked" result by hand, and the d1 score reflects that correction.
5. **Defenses can block legitimate email.** The first version of the link filter treated the domain inside email addresses (e.g. `finance@harmonyhr.com`) as links and flagged 2 of 18 normal emails. I fixed it by ignoring domains that follow an `@`.

## Limitations

- **Small sample, mostly single runs.** LLM output varies between runs, so treat the numbers as indicative.
- **Defenses were written with knowledge of the test set.** A real attacker would adapt, so 0/20 means "these 20 attacks failed", not "the system is secure".
- **Promises in reply text aren't enforced in code.** The guard can't reliably detect a made-up refund promise, so reply drafts should be reviewed by a human before sending.
- **Category accuracy (13/18) is a separate problem.** Bug reports are often labelled "support" because the prompt never defines the categories. It didn't change across versions, which suggests the defenses didn't hurt classification.

## Run it yourself

1. Start n8n, import `workflow.json` and `error-workflow.json`, and add your own Groq, Airtable and Telegram credentials.
2. In the main workflow's settings, set the error workflow to `Inbox Triage – Error Alerts`, then publish.
3. Run:
   ```
   pip install requests
   python run_attacks.py <label>
   ```

All senders, companies and domains in the dataset are fictional.
