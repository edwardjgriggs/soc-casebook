# Case brute-force-then-success: Password guessing then a successful sign-in for the finance director

Detection **Brute force then success on one account** (T1110.001, High) fired at 2026-10-27T13:20:00Z. Lab case: built from the detection's known-bad fixture, enriched against the fictional Harborline Federal directory.

## 1. Verdict and summary

|  | Verdict | Severity |
|---|---|---|
| Final (human) | **True positive** | Critical |
| AI first pass | True positive (high confidence) | Critical |

Edward Griggs agrees with the AI.

Nine consecutive failed sign-ins (50126, invalid username or password) for Priya Nair, the Finance Director, came from 203.0.113.50 at 20-second intervals between 13:00:00Z and 13:02:40Z. A successful sign-in (ResultType 0) from the same IP followed at 13:03:10Z. The IP is a bulletproof hosting provider in Russia (AS64530) that enrichment marks malicious and a known password-guessing source across many tenants. It is not in her known IPs, and RU is outside her usual countries (US, CA). The regular cadence points to automated guessing, and the success right after the failures means the password was very likely guessed. Her only MFA method is Authenticator push, and the alert does not show whether MFA was challenged or satisfied on the success, so it is unclear whether the attacker holds a full session or only the password. She is a finance director at a CUI-holding contractor, so the account should be treated as compromised until shown otherwise.

## 2. Timeline

| Time (UTC) | Event | Source |
|---|---|---|
| 2026-10-27T13:00:00Z | First failed sign-in (50126) for priya.nair from 203.0.113.50 | AI, from evidence |
| 2026-10-27T13:00:20Z - 13:02:40Z | Seven more failures at a steady 20-second cadence, nine in total, all from the same IP | AI, from evidence |
| 2026-10-27T13:03:10Z | Successful sign-in (ResultType 0) from 203.0.113.50, 30 seconds after the last failure | AI, from evidence |
| 2026-10-27T13:20:00Z | Detection fired, 17 minutes after the successful sign-in | AI, from evidence |
| 2026-10-27T13:20:00Z | Detection fired: Brute force then success on one account | SIEM |
| 2026-10-29T04:01:52Z | AI assessment recorded (claude-sonnet-5-5) | casebook |
| 2026-10-29T13:34:55Z | Decision by Edward Griggs: True positive | analyst |

## 3. Evidence

### Detection output

| Field | Value |
|---|---|
| UserPrincipalName | priya.nair@harborline.example |
| FailCount | 9 |
| FailIPs | `["203.0.113.50"]` |
| FirstFail | 2026-10-27T13:00:00Z |
| LastFail | 2026-10-27T13:02:40Z |
| SuccessTime | 2026-10-27T13:03:10Z |
| SuccessIP | 203.0.113.50 |

### Log rows that fired (SigninLogs, 10 rows)

| TimeGenerated | ResultType | UserPrincipalName | IPAddress |
|---|---|---|---|
| 2026-10-27T13:00:00Z | 50126 | priya.nair@harborline.example | 203.0.113.50 |
| 2026-10-27T13:00:20Z | 50126 | priya.nair@harborline.example | 203.0.113.50 |
| 2026-10-27T13:00:40Z | 50126 | priya.nair@harborline.example | 203.0.113.50 |
| 2026-10-27T13:01:00Z | 50126 | priya.nair@harborline.example | 203.0.113.50 |
| 2026-10-27T13:01:20Z | 50126 | priya.nair@harborline.example | 203.0.113.50 |
| 2026-10-27T13:01:40Z | 50126 | priya.nair@harborline.example | 203.0.113.50 |
| 2026-10-27T13:02:00Z | 50126 | priya.nair@harborline.example | 203.0.113.50 |
| 2026-10-27T13:02:20Z | 50126 | priya.nair@harborline.example | 203.0.113.50 |
| 2026-10-27T13:02:40Z | 50126 | priya.nair@harborline.example | 203.0.113.50 |
| 2026-10-27T13:03:10Z | 0 | priya.nair@harborline.example | 203.0.113.50 |

### Enrichment

| User | In directory | Title | Admin | MFA methods | Usual countries | Alert IPs new for user |
|---|---|---|---|---|---|---|
| priya.nair@harborline.example | yes | Finance Director | no | `["Microsoft Authenticator push"]` | `["US","CA"]` | `["203.0.113.50"]` |

| IP | Known | Country | Owner | Reputation | Notes |
|---|---|---|---|---|---|
| 203.0.113.50 | yes | RU | Bulletproof hosting provider | malicious | Known password-guessing source across many tenants in the last 30 days. |

## 4. AI assessment

Model: `claude-sonnet-5-5`. Verdict **True positive**, confidence **high**, severity **Critical**.

**Key evidence**

- 9 failures with ResultType 50126 from 203.0.113.50 between 13:00:00Z and 13:02:40Z, spaced exactly 20 seconds apart, which indicates scripted guessing
- ResultType 0 from the same IP at 13:03:10Z, 30 seconds after the last failure
- IP reputation is malicious: bulletproof hosting provider (AS64530), country RU, known password-guessing source across many tenants in the last 30 days
- 203.0.113.50 is not among the user's known IPs (198.51.100.10, 192.0.2.44), and RU is outside her usual countries (US, CA)
- The user's notes mention only quarterly travel to Canada, which does not explain a Russian source
- Target is the Finance Director with a single MFA method (Microsoft Authenticator push), which raises the value of the account and exposes it to MFA fatigue or token abuse if MFA was prompted
- No application entities are present, so the alert does not show what the successful session accessed

**Benign explanations considered**

- Legitimate user mistyping her password: ruled out by the 9 failures at machine-regular 20-second intervals from a malicious-reputation IP that she has never used
- User traveling or using a VPN: her documented travel is to Canada, and the source is a bulletproof hosting provider in RU, not a commercial VPN or her usual countries
- Security testing or an authorized red team: nothing in the alert or enrichment indicates an authorized test, though that is unconfirmed with the security team
- Misconfigured service or script with a stale password: it would not come from a known malicious guessing source and would not be tied to a user who has never signed in from this IP
- Success being a different actor: the success comes from the same IP 30 seconds after the failures, so it is almost certainly the same actor

**Recommended actions**

| Action | Target | Rationale |
|---|---|---|
| revoke_sessions | priya.nair@harborline.example | Invalidates any refresh or session tokens the attacker obtained from the 13:03:10Z successful sign-in. |
| reset_password | priya.nair@harborline.example | The password was almost certainly guessed and must be considered known to the attacker. |
| block_ip | 203.0.113.50 | A malicious-reputation password-guessing source should be blocked at the tenant, for example in a Conditional Access named location, to prevent further attempts. |
| require_mfa_reregistration | priya.nair@harborline.example | If the attacker satisfied or manipulated an MFA prompt, or registered their own method, the existing registration cannot be trusted. Do this after reviewing the MFA events for the account. |
| notify_user | priya.nair@harborline.example | Contact her out of band to confirm she did not sign in at 13:03Z, to ask whether she approved any unexpected Authenticator prompts, and to inform her of the reset. |

**Open questions**

- Was MFA challenged on the 13:03:10Z sign-in, and if so was it completed, and by what method?
- Did the user receive unexpected Authenticator push prompts around 13:03Z?
- What did the session do after 13:03:10Z (mailbox access, inbox rules, file downloads from SharePoint/OneDrive, OAuth consent, MFA method registration)?
- Did 203.0.113.50 attempt sign-ins against other Harborline accounts?
- Was the account's password reused elsewhere or exposed in a known breach?
- Did the sign-in reach any CUI repositories or finance systems?

<details><summary>Verbatim model output</summary>

```json
{
  "verdict": "true_positive",
  "confidence": "high",
  "severity": "Critical",
  "summary": "Nine consecutive failed sign-ins (50126, invalid username or password) for Priya Nair, the Finance Director, came from 203.0.113.50 at 20-second intervals between 13:00:00Z and 13:02:40Z. A successful sign-in (ResultType 0) from the same IP followed at 13:03:10Z. The IP is a bulletproof hosting provider in Russia (AS64530) that enrichment marks malicious and a known password-guessing source across many tenants. It is not in her known IPs, and RU is outside her usual countries (US, CA). The regular cadence points to automated guessing, and the success right after the failures means the password was very likely guessed. Her only MFA method is Authenticator push, and the alert does not show whether MFA was challenged or satisfied on the success, so it is unclear whether the attacker holds a full session or only the password. She is a finance director at a CUI-holding contractor, so the account should be treated as compromised until shown otherwise.",
  "timeline": [
    {
      "time": "2026-10-27T13:00:00Z",
      "event": "First failed sign-in (50126) for priya.nair from 203.0.113.50"
    },
    {
      "time": "2026-10-27T13:00:20Z - 13:02:40Z",
      "event": "Seven more failures at a steady 20-second cadence, nine in total, all from the same IP"
    },
    {
      "time": "2026-10-27T13:03:10Z",
      "event": "Successful sign-in (ResultType 0) from 203.0.113.50, 30 seconds after the last failure"
    },
    {
      "time": "2026-10-27T13:20:00Z",
      "event": "Detection fired, 17 minutes after the successful sign-in"
    }
  ],
  "key_evidence": [
    "9 failures with ResultType 50126 from 203.0.113.50 between 13:00:00Z and 13:02:40Z, spaced exactly 20 seconds apart, which indicates scripted guessing",
    "ResultType 0 from the same IP at 13:03:10Z, 30 seconds after the last failure",
    "IP reputation is malicious: bulletproof hosting provider (AS64530), country RU, known password-guessing source across many tenants in the last 30 days",
    "203.0.113.50 is not among the user's known IPs (198.51.100.10, 192.0.2.44), and RU is outside her usual countries (US, CA)",
    "The user's notes mention only quarterly travel to Canada, which does not explain a Russian source",
    "Target is the Finance Director with a single MFA method (Microsoft Authenticator push), which raises the value of the account and exposes it to MFA fatigue or token abuse if MFA was prompted",
    "No application entities are present, so the alert does not show what the successful session accessed"
  ],
  "benign_explanations_considered": [
    "Legitimate user mistyping her password: ruled out by the 9 failures at machine-regular 20-second intervals from a malicious-reputation IP that she has never used",
    "User traveling or using a VPN: her documented travel is to Canada, and the source is a bulletproof hosting provider in RU, not a commercial VPN or her usual countries",
    "Security testing or an authorized red team: nothing in the alert or enrichment indicates an authorized test, though that is unconfirmed with the security team",
    "Misconfigured service or script with a stale password: it would not come from a known malicious guessing source and would not be tied to a user who has never signed in from this IP",
    "Success being a different actor: the success comes from the same IP 30 seconds after the failures, so it is almost certainly the same actor"
  ],
  "recommended_actions": [
    {
      "action": "revoke_sessions",
      "target": "priya.nair@harborline.example",
      "rationale": "Invalidates any refresh or session tokens the attacker obtained from the 13:03:10Z successful sign-in."
    },
    {
      "action": "reset_password",
      "target": "priya.nair@harborline.example",
      "rationale": "The password was almost certainly guessed and must be considered known to the attacker."
    },
    {
      "action": "block_ip",
      "target": "203.0.113.50",
      "rationale": "A malicious-reputation password-guessing source should be blocked at the tenant, for example in a Conditional Access named location, to prevent further attempts."
    },
    {
      "action": "require_mfa_reregistration",
      "target": "priya.nair@harborline.example",
      "rationale": "If the attacker satisfied or manipulated an MFA prompt, or registered their own method, the existing registration cannot be trusted. Do this after reviewing the MFA events for the account."
    },
    {
      "action": "notify_user",
      "target": "priya.nair@harborline.example",
      "rationale": "Contact her out of band to confirm she did not sign in at 13:03Z, to ask whether she approved any unexpected Authenticator prompts, and to inform her of the reset."
    }
  ],
  "attack_mapping": [
    {
      "technique_id": "T1110.001",
      "technique_name": "Brute Force: Password Guessing",
      "tactic": "Credential Access"
    },
    {
      "technique_id": "T1078.004",
      "technique_name": "Valid Accounts: Cloud Accounts",
      "tactic": "Initial Access"
    }
  ],
  "detection_tuning_notes": [
    "The rule worked well: a short failure burst followed by a success from the same IP, combined with IP reputation and user-context enrichment, gave a clear signal",
    "Consider raising severity automatically when the success IP has a malicious reputation or is outside the user's known IPs and countries",
    "Add MFA outcome fields (for example AuthenticationRequirement and ConditionalAccessStatus) to the output so triage can tell whether the success was password-only or MFA-satisfied",
    "Add a query for post-success activity (mailbox rules, OAuth grants, MFA method changes, file access) to speed up scoping",
    "A single-account burst from one IP may miss low-and-slow spraying; consider a companion rule for one IP failing across many accounts"
  ],
  "open_questions": [
    "Was MFA challenged on the 13:03:10Z sign-in, and if so was it completed, and by what method?",
    "Did the user receive unexpected Authenticator push prompts around 13:03Z?",
    "What did the session do after 13:03:10Z (mailbox access, inbox rules, file downloads from SharePoint/OneDrive, OAuth consent, MFA method registration)?",
    "Did 203.0.113.50 attempt sign-ins against other Harborline accounts?",
    "Was the account's password reused elsewhere or exposed in a known breach?",
    "Did the sign-in reach any CUI repositories or finance systems?"
  ]
}
```

</details>

## 5. Human decision and rationale

**Analyst:** Edward Griggs  
**Decided:** 2026-10-29T13:34:55Z  
**Verdict:** True positive (Critical)

Agree with the AI, including Critical. Nine wrong passwords at machine cadence from a bulletproof host with a malicious reputation, then a success from the same IP 30 seconds later: the password was guessed. The open question is MFA. The success row does not say whether push was satisfied, so assume the attacker has a session. She is the finance director at a CUI contractor, which makes her mailbox a payment-fraud target as well as a data target.

## 6. Actions

| Action | Target | Recommended by | Decision | Approver | Reason |
|---|---|---|---|---|---|
| revoke_sessions | priya.nair@harborline.example | AI | **approved** | Edward Griggs | Kill whatever session the 13:03:10Z sign-in produced. |
| reset_password | priya.nair@harborline.example | AI | **approved** | Edward Griggs | The password was guessed. |
| block_ip | 203.0.113.50 | AI | **approved** | Edward Griggs | Hosting provider with a malicious reputation, not residential space. No business traffic will come from it, so the block has no collateral. |
| require_mfa_reregistration | priya.nair@harborline.example | AI | **approved** | Edward Griggs | Until the sign-in logs show how MFA was satisfied, her registered methods cannot be trusted. |
| notify_user | priya.nair@harborline.example | AI | **approved** | Edward Griggs | Confirm by phone, not email, since the mailbox may be in the attacker's hands. |
| disable_account | priya.nair@harborline.example | Analyst | **approved** | Edward Griggs | Hold the account disabled until she is reached by phone and the reset is done with her. Revoking sessions does not stop a fresh sign-in with a known password in the gap before the reset lands. |

The AI executed nothing. Approved actions are carried out by the analyst.

## 7. ATT&CK mapping

| Technique | Name | Tactic | Mapped by |
|---|---|---|---|
| [T1110.001](https://attack.mitre.org/techniques/T1110/001/) | Password Guessing | Credential Access | Detection |
| [T1110.001](https://attack.mitre.org/techniques/T1110/001/) | Brute Force: Password Guessing | Credential Access | AI |
| [T1078.004](https://attack.mitre.org/techniques/T1078/004/) | Valid Accounts: Cloud Accounts | Initial Access | AI |

## 8. Detection tuning notes

Rule `8e21a6b0-3c4d-4f19-91aa-7d2e5c8f3012` lives in [detection-as-code](https://github.com/edwardjgriggs/detection-as-code).

**Analyst**

- Add AuthenticationRequirement and ConditionalAccessStatus to the output. The analyst should not have to open a second query to learn whether the success was password-only.

**AI**

- The rule worked well: a short failure burst followed by a success from the same IP, combined with IP reputation and user-context enrichment, gave a clear signal
- Consider raising severity automatically when the success IP has a malicious reputation or is outside the user's known IPs and countries
- Add MFA outcome fields (for example AuthenticationRequirement and ConditionalAccessStatus) to the output so triage can tell whether the success was password-only or MFA-satisfied
- Add a query for post-success activity (mailbox rules, OAuth grants, MFA method changes, file access) to speed up scoping
- A single-account burst from one IP may miss low-and-slow spraying; consider a companion rule for one IP failing across many accounts
