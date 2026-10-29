# Case mfa-fatigue-burst: MFA prompt burst against a contracts manager

Detection **MFA fatigue burst** (T1621, High) fired at 2026-10-27T17:10:00Z. Lab case: built from the detection's known-bad fixture, enriched against the fictional Harborline Federal directory.

## 1. Verdict and summary

|  | Verdict | Severity |
|---|---|---|
| Final (human) | **True positive** | High |
| AI first pass | True positive (high confidence) | High |

Edward Griggs agrees with the AI.

Ten MFA-interrupted sign-in attempts for Ada Marsh (Contracts Manager, handles CUI-marked proposal material) arrived from 203.0.113.7 between 17:00:00Z and 17:03:00Z, one every 20 seconds. The IP is a rotating residential proxy exit in the NL, flagged suspicious and seen in other tenants' MFA-prompt bombing reports. Ada works from Virginia, her usual country is US, and this IP is not in her known IPs. Reaching the MFA stage normally means the primary credential was accepted, so the password is probably compromised. The supplied rows show no successful sign-in (ResultType 0) and no completed approval, but that is not confirmed for the 7 minutes between the last row and the 17:10Z alert, or afterwards. Treat as an active MFA-fatigue attempt against a valid password until a human confirms no approval occurred.

## 2. Timeline

| Time (UTC) | Event | Source |
|---|---|---|
| 2026-10-27T17:00:00Z | First sign-in attempt from 203.0.113.7 interrupted by MFA requirement (50074). | AI, from evidence |
| 2026-10-27T17:00:20Z-17:01:40Z | Five more 50074 events at exactly 20-second intervals, suggesting automated retries. | AI, from evidence |
| 2026-10-27T17:02:00Z | Result code changes to 50076 (MFA required) for the same user and IP, with the same cadence. | AI, from evidence |
| 2026-10-27T17:03:00Z | Tenth and last event in the evidence (50076). The burst totals 10 events over 3 minutes, with no success row. | AI, from evidence |
| 2026-10-27T17:10:00Z | Detection fired. Activity after 17:03Z is not included in the evidence. | AI, from evidence |
| 2026-10-27T17:10:00Z | Detection fired: MFA fatigue burst | SIEM |
| 2026-10-29T04:01:33Z | AI assessment recorded (claude-sonnet-5-5) | casebook |
| 2026-10-29T13:34:55Z | Decision by Edward Griggs: True positive | analyst |

## 3. Evidence

### Detection output

| Field | Value |
|---|---|
| TimeGenerated | 2026-10-27T17:00:00Z |
| UserPrincipalName | ada.marsh@harborline.example |
| PromptEvents | 10 |
| IPs | `["203.0.113.7"]` |
| Codes | `["50074","50076"]` |

### Log rows that fired (SigninLogs, 10 rows)

| TimeGenerated | ResultType | UserPrincipalName | IPAddress | Status |
|---|---|---|---|---|
| 2026-10-27T17:00:00Z | 50074 | ada.marsh@harborline.example | 203.0.113.7 | `{"errorCode":50074}` |
| 2026-10-27T17:00:20Z | 50074 | ada.marsh@harborline.example | 203.0.113.7 | `{"errorCode":50074}` |
| 2026-10-27T17:00:40Z | 50074 | ada.marsh@harborline.example | 203.0.113.7 | `{"errorCode":50074}` |
| 2026-10-27T17:01:00Z | 50074 | ada.marsh@harborline.example | 203.0.113.7 | `{"errorCode":50074}` |
| 2026-10-27T17:01:20Z | 50074 | ada.marsh@harborline.example | 203.0.113.7 | `{"errorCode":50074}` |
| 2026-10-27T17:01:40Z | 50074 | ada.marsh@harborline.example | 203.0.113.7 | `{"errorCode":50074}` |
| 2026-10-27T17:02:00Z | 50076 | ada.marsh@harborline.example | 203.0.113.7 | `{"errorCode":50076}` |
| 2026-10-27T17:02:20Z | 50076 | ada.marsh@harborline.example | 203.0.113.7 | `{"errorCode":50076}` |
| 2026-10-27T17:02:40Z | 50076 | ada.marsh@harborline.example | 203.0.113.7 | `{"errorCode":50076}` |
| 2026-10-27T17:03:00Z | 50076 | ada.marsh@harborline.example | 203.0.113.7 | `{"errorCode":50076}` |

### Enrichment

| User | In directory | Title | Admin | MFA methods | Usual countries | Alert IPs new for user |
|---|---|---|---|---|---|---|
| ada.marsh@harborline.example | yes | Contracts Manager | no | `["Microsoft Authenticator push"]` | `["US"]` | `["203.0.113.7"]` |

| IP | Known | Country | Owner | Reputation | Notes |
|---|---|---|---|---|---|
| 203.0.113.7 | yes | NL | Residential proxy network | suspicious | Rotating residential proxy exit. Seen in other tenants' MFA-prompt bombing reports. |

## 4. AI assessment

Model: `claude-sonnet-5-5`. Verdict **True positive**, confidence **high**, severity **High**.

**Key evidence**

- 10 events in 3 minutes from a single IP, spaced exactly 20 seconds apart. The regular cadence points to scripted prompt generation, not a person retrying.
- 203.0.113.7 is a residential proxy exit (AS64520, NL) rated suspicious, with notes saying it has appeared in other tenants' MFA-prompt bombing reports.
- The IP is not among Ada's known IPs (198.51.100.10, 198.51.100.24), and NL is outside her usual country (US). She works hybrid from Virginia.
- Her only MFA method is Microsoft Authenticator push, which is the method exposed to prompt-bombing and approval-by-fatigue.
- Codes 50074 and 50076 are MFA-required results, which are normally returned after the first factor is accepted. This suggests the attacker already has her password.
- Ada is a non-admin who handles subcontractor agreements and CUI-marked material, so a compromise puts CUI at risk under the NIST SP 800-171 obligations.
- No ResultType 0 and no 500121 (MFA denied/failed) appear in the evidence, so the outcome of the prompts is unknown.

**Benign explanations considered**

- Ada herself signing in through a VPN or while traveling: the IP is a known residential proxy rated suspicious, she works from Virginia, and 10 prompts at fixed 20-second intervals do not look like a person logging in.
- A stale or misconfigured client (cached token, legacy app, mail client) retrying automatically: possible given the regular cadence, but the source is an NL proxy exit, not one of her known IPs, so it is unlikely. User agent and client app are not in the evidence.
- Policy or configuration change forcing re-registration or a new-location MFA prompt (50076 wording): this would not explain the proxy IP or the repeated prompts over 3 minutes.
- A red-team or penetration test: no evidence of authorization is provided. Confirm with management before downgrading.

**Recommended actions**

| Action | Target | Rationale |
|---|---|---|
| reset_password | ada.marsh@harborline.example | MFA-stage results imply the first factor was accepted from the attacker's IP, so the password should be treated as known to the attacker. |
| revoke_sessions | ada.marsh@harborline.example | Invalidate refresh tokens and sessions in case any prompt was approved after 17:03Z or a session was already established. |
| block_ip | 203.0.113.7 | Known suspicious proxy exit tied to MFA-bombing in other tenants. This is a low-cost block, though rotating exits limit its value. |
| notify_user | ada.marsh@harborline.example | Ask whether she received or approved any unexpected Authenticator prompts around 17:00-17:03Z, and tell her not to approve unsolicited prompts. Contact her by a channel other than email or Teams in case the account is compromised. |

**Open questions**

- Did any sign-in from 203.0.113.7 or any other unknown IP succeed for this user after 17:03Z (ResultType 0)? Were there any approved Authenticator prompts in the MFA activity logs?
- Did Ada receive and approve any Authenticator prompts, and did she report any?
- How was the password obtained (phishing, credential stuffing, reuse, infostealer)? Is there earlier password-spray or failed-password (50126) activity against her or others from this IP?
- Were any other Harborline users targeted from 203.0.113.7 or AS64520?
- What were the client app, user agent, and target resource for these attempts?
- If a session was established, were there mailbox rule creations, new MFA method registrations, or SharePoint/OneDrive access to CUI after 17:03Z? If any prompt was approved, MFA re-registration should be added to the actions.

<details><summary>Verbatim model output</summary>

```json
{
  "verdict": "true_positive",
  "confidence": "high",
  "severity": "High",
  "summary": "Ten MFA-interrupted sign-in attempts for Ada Marsh (Contracts Manager, handles CUI-marked proposal material) arrived from 203.0.113.7 between 17:00:00Z and 17:03:00Z, one every 20 seconds. The IP is a rotating residential proxy exit in the NL, flagged suspicious and seen in other tenants' MFA-prompt bombing reports. Ada works from Virginia, her usual country is US, and this IP is not in her known IPs. Reaching the MFA stage normally means the primary credential was accepted, so the password is probably compromised. The supplied rows show no successful sign-in (ResultType 0) and no completed approval, but that is not confirmed for the 7 minutes between the last row and the 17:10Z alert, or afterwards. Treat as an active MFA-fatigue attempt against a valid password until a human confirms no approval occurred.",
  "timeline": [
    {
      "time": "2026-10-27T17:00:00Z",
      "event": "First sign-in attempt from 203.0.113.7 interrupted by MFA requirement (50074)."
    },
    {
      "time": "2026-10-27T17:00:20Z-17:01:40Z",
      "event": "Five more 50074 events at exactly 20-second intervals, suggesting automated retries."
    },
    {
      "time": "2026-10-27T17:02:00Z",
      "event": "Result code changes to 50076 (MFA required) for the same user and IP, with the same cadence."
    },
    {
      "time": "2026-10-27T17:03:00Z",
      "event": "Tenth and last event in the evidence (50076). The burst totals 10 events over 3 minutes, with no success row."
    },
    {
      "time": "2026-10-27T17:10:00Z",
      "event": "Detection fired. Activity after 17:03Z is not included in the evidence."
    }
  ],
  "key_evidence": [
    "10 events in 3 minutes from a single IP, spaced exactly 20 seconds apart. The regular cadence points to scripted prompt generation, not a person retrying.",
    "203.0.113.7 is a residential proxy exit (AS64520, NL) rated suspicious, with notes saying it has appeared in other tenants' MFA-prompt bombing reports.",
    "The IP is not among Ada's known IPs (198.51.100.10, 198.51.100.24), and NL is outside her usual country (US). She works hybrid from Virginia.",
    "Her only MFA method is Microsoft Authenticator push, which is the method exposed to prompt-bombing and approval-by-fatigue.",
    "Codes 50074 and 50076 are MFA-required results, which are normally returned after the first factor is accepted. This suggests the attacker already has her password.",
    "Ada is a non-admin who handles subcontractor agreements and CUI-marked material, so a compromise puts CUI at risk under the NIST SP 800-171 obligations.",
    "No ResultType 0 and no 500121 (MFA denied/failed) appear in the evidence, so the outcome of the prompts is unknown."
  ],
  "benign_explanations_considered": [
    "Ada herself signing in through a VPN or while traveling: the IP is a known residential proxy rated suspicious, she works from Virginia, and 10 prompts at fixed 20-second intervals do not look like a person logging in.",
    "A stale or misconfigured client (cached token, legacy app, mail client) retrying automatically: possible given the regular cadence, but the source is an NL proxy exit, not one of her known IPs, so it is unlikely. User agent and client app are not in the evidence.",
    "Policy or configuration change forcing re-registration or a new-location MFA prompt (50076 wording): this would not explain the proxy IP or the repeated prompts over 3 minutes.",
    "A red-team or penetration test: no evidence of authorization is provided. Confirm with management before downgrading."
  ],
  "recommended_actions": [
    {
      "action": "reset_password",
      "target": "ada.marsh@harborline.example",
      "rationale": "MFA-stage results imply the first factor was accepted from the attacker's IP, so the password should be treated as known to the attacker."
    },
    {
      "action": "revoke_sessions",
      "target": "ada.marsh@harborline.example",
      "rationale": "Invalidate refresh tokens and sessions in case any prompt was approved after 17:03Z or a session was already established."
    },
    {
      "action": "block_ip",
      "target": "203.0.113.7",
      "rationale": "Known suspicious proxy exit tied to MFA-bombing in other tenants. This is a low-cost block, though rotating exits limit its value."
    },
    {
      "action": "notify_user",
      "target": "ada.marsh@harborline.example",
      "rationale": "Ask whether she received or approved any unexpected Authenticator prompts around 17:00-17:03Z, and tell her not to approve unsolicited prompts. Contact her by a channel other than email or Teams in case the account is compromised."
    }
  ],
  "attack_mapping": [
    {
      "technique_id": "T1621",
      "technique_name": "Multi-Factor Authentication Request Generation",
      "tactic": "Credential Access"
    },
    {
      "technique_id": "T1078.004",
      "technique_name": "Valid Accounts: Cloud Accounts",
      "tactic": "Initial Access"
    },
    {
      "technique_id": "T1090.002",
      "technique_name": "Proxy: External Proxy",
      "tactic": "Command and Control"
    }
  ],
  "detection_tuning_notes": [
    "The rule is useful here. It combines a high prompt count, a short window, and a single source IP, and the enrichment (proxy reputation, unknown IP, unusual country) confirms intent.",
    "The rule fired at 17:10Z, 7 minutes after the last event. Reducing latency would help, since an approved prompt gives the attacker a session within seconds.",
    "Add a correlation step that checks for ResultType 0 (or a successful MFA completion) for the same user after the burst, from the same IP or any new IP, and raise severity to Critical if found.",
    "The rule matches 50074 and 50076, which are MFA-required results and not proof that a push was sent or denied. Consider also counting 500121 (MFA denied/failed) and 50072/50158-type results, and show the user's MFA method in the output so push-based users are prioritized.",
    "Include UserAgent, ClientAppUsed, and location columns in the output so the analyst can quickly tell a script from a stale client.",
    "Join the IP reputation feed in the rule itself so proxy-exit IPs auto-raise severity. Also consider alerting on multiple users hit from the same IP."
  ],
  "open_questions": [
    "Did any sign-in from 203.0.113.7 or any other unknown IP succeed for this user after 17:03Z (ResultType 0)? Were there any approved Authenticator prompts in the MFA activity logs?",
    "Did Ada receive and approve any Authenticator prompts, and did she report any?",
    "How was the password obtained (phishing, credential stuffing, reuse, infostealer)? Is there earlier password-spray or failed-password (50126) activity against her or others from this IP?",
    "Were any other Harborline users targeted from 203.0.113.7 or AS64520?",
    "What were the client app, user agent, and target resource for these attempts?",
    "If a session was established, were there mailbox rule creations, new MFA method registrations, or SharePoint/OneDrive access to CUI after 17:03Z? If any prompt was approved, MFA re-registration should be added to the actions."
  ]
}
```

</details>

## 5. Human decision and rationale

**Analyst:** Edward Griggs  
**Decided:** 2026-10-29T13:34:55Z  
**Verdict:** True positive (High)

Agree with the AI. Ten MFA-required results in three minutes from a residential proxy exit Ada has never used, at a fixed 20-second cadence, is scripted prompt bombing, not a user fighting a stale client. Results 50074 and 50076 only appear after the password is accepted, so the password is burned even though no prompt was approved in the window. Contain the account, not the IP.

## 6. Actions

| Action | Target | Recommended by | Decision | Approver | Reason |
|---|---|---|---|---|---|
| reset_password | ada.marsh@harborline.example | AI | **approved** | Edward Griggs | First factor was accepted from the attacker's IP. The password is known. |
| revoke_sessions | ada.marsh@harborline.example | AI | **approved** | Edward Griggs | Cheap insurance against an approval after 17:03Z that the alert window did not show. |
| block_ip | 203.0.113.7 | AI | **rejected** | Edward Griggs | Rotating residential proxy. The next attempt comes from a different exit, and blocking residential space risks real users. The control that matters is on the account. |
| notify_user | ada.marsh@harborline.example | AI | **approved** | Edward Griggs | Confirm out of band that she denied every prompt and tell her to report the next one. |

The AI executed nothing. Approved actions are carried out by the analyst.

## 7. ATT&CK mapping

| Technique | Name | Tactic | Mapped by |
|---|---|---|---|
| [T1621](https://attack.mitre.org/techniques/T1621/) | Multi-Factor Authentication Request Generation | Credential Access | Detection |
| [T1621](https://attack.mitre.org/techniques/T1621/) | Multi-Factor Authentication Request Generation | Credential Access | AI |
| [T1078.004](https://attack.mitre.org/techniques/T1078/004/) | Valid Accounts: Cloud Accounts | Initial Access | AI |
| [T1090.002](https://attack.mitre.org/techniques/T1090/002/) | Proxy: External Proxy | Command and Control | AI |

## 8. Detection tuning notes

Rule `9a3e1c70-5d2b-4e18-af44-1c6b8d0e3925` lives in [detection-as-code](https://github.com/edwardjgriggs/detection-as-code).

**Analyst**

- Seven minutes from last prompt to alert is too slow for push fatigue; one approval gives the attacker a session in seconds. Move this rule to near-real-time.

**AI**

- The rule is useful here. It combines a high prompt count, a short window, and a single source IP, and the enrichment (proxy reputation, unknown IP, unusual country) confirms intent.
- The rule fired at 17:10Z, 7 minutes after the last event. Reducing latency would help, since an approved prompt gives the attacker a session within seconds.
- Add a correlation step that checks for ResultType 0 (or a successful MFA completion) for the same user after the burst, from the same IP or any new IP, and raise severity to Critical if found.
- The rule matches 50074 and 50076, which are MFA-required results and not proof that a push was sent or denied. Consider also counting 500121 (MFA denied/failed) and 50072/50158-type results, and show the user's MFA method in the output so push-based users are prioritized.
- Include UserAgent, ClientAppUsed, and location columns in the output so the analyst can quickly tell a script from a stale client.
- Join the IP reputation feed in the rule itself so proxy-exit IPs auto-raise severity. Also consider alerting on multiple users hit from the same IP.
