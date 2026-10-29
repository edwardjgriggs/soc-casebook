# Case oauth-consent-high-privilege: User consent to a mail-access app named like the e-signature vendor

Detection **High-privilege OAuth consent** (T1528, High) fired at 2026-10-27T18:15:00Z. Lab case: built from the detection's known-bad fixture, enriched against the fictional Harborline Federal directory.

## 1. Verdict and summary

|  | Verdict | Severity |
|---|---|---|
| Final (human) | **True positive** | Critical |
| AI first pass | Needs more info (low confidence) | High |

Edward Griggs **overrides the AI** (AI said: Needs more info, low confidence).

Ada Marsh (Contracts Manager, non-admin, handles CUI-marked proposal material) consented as herself at 18:00:00Z on 2026-10-27 to 'Northwind eSign for Outlook', granting Mail.ReadWrite and offline_access (persistent refresh token). The app (client ID e93b5c1d-7a40-4d2f-b8e6-0c3a91f5d274) is not found in the organization's app catalog. The user, IP, and consent type look normal (known VPN IP, usual country, not admin consent, not tenant-wide), and a contracts manager could plausibly want an e-signature add-in. But the unvetted app, the broad mailbox read/write scope, the persistent token, and the vendor-style name (a common lure for illicit consent grants) mean the activity cannot be called benign. The evidence also cannot prove it malicious: it shows no sign-in anomaly, no post-consent mailbox activity, and no verified publisher. Treat as potentially risky until the app's legitimacy is established.

## 2. Timeline

| Time (UTC) | Event | Source |
|---|---|---|
| 2026-10-27T18:00:00Z | ada.marsh@harborline.example consented (user consent, not admin, not on behalf of all) to 'Northwind eSign for Outlook' with scopes Mail.ReadWrite, offline_access, User.Read, openid, profile, from 198.51.100.24 (Harborline VPN). Result: success. | AI, from evidence |
| 2026-10-27T18:15:00Z | High-privilege OAuth consent detection fired. | AI, from evidence |
| 2026-10-27T18:15:00Z | Detection fired: High-privilege OAuth consent | SIEM |
| 2026-10-29T04:02:14Z | AI assessment recorded (claude-sonnet-5-5) | casebook |
| 2026-10-29T13:34:56Z | Decision by Edward Griggs: True positive | analyst |

## 3. Evidence

### Detection output

| Field | Value |
|---|---|
| TimeGenerated | 2026-10-27T18:00:00Z |
| OperationName | Consent to application |
| Result | success |
| InitiatedBy | ada.marsh@harborline.example |
| Targets | [{"id":"5f0d2a8c-91b3-4e67-a4d1-7c2e8b9f3a60","type":"ServicePrincipal","displayName":"Northwind eSign for Outlook","modifiedProperties":[{"displayName":"ConsentContext.IsAdminConsent","newValue":"False"},{"displayName":"ConsentContext.OnBehalfOfAll","newValue":"False"},{"displayName":"ConsentAction.Permissions","newValue":"Scope: Mail.ReadWrite offline_access User.Read openid profile"},{"displayName":"TargetId.ServicePrincipalNames","newValue":"e93b5c1d-7a40-4d2f-b8e6-0c3a91f5d274"}]}] |
| CorrelationId | 3c7e9a14-2b5f-4d08-9e61-a8f04c2d7b95 |

### Log rows that fired (AuditLogs, 1 row)

| TimeGenerated | OperationName | Result | InitiatedBy | TargetResources | CorrelationId |
|---|---|---|---|---|---|
| 2026-10-27T18:00:00Z | Consent to application | success | `{"user":{"userPrincipalName":"ada.marsh@harborline.example","ipAddress":"198.51.100.24"}}` | `[{"id":"5f0d2a8c-91b3-4e67-a4d1-7c2e8b9f3a60","type":"ServicePrincipal","displayName":"Northwind eSign for Outlook","modifiedProperties":[{"displayName":"ConsentContext.IsAdminConsent","newValue":"False"},{"displayName":"ConsentContext.OnBehalfOfAll","newValue":"False"},{"displayName":"ConsentAction.Permissions","newValue":"Scope: Mail.ReadWrite offline_access User.Read openid profile"},{"displayName":"TargetId.ServicePrincipalNames","newValue":"e93b5c1d-7a40-4d2f-b8e6-0c3a91f5d274"}]}]` | 3c7e9a14-2b5f-4d08-9e61-a8f04c2d7b95 |

### Enrichment

| User | In directory | Title | Admin | MFA methods | Usual countries | Alert IPs new for user |
|---|---|---|---|---|---|---|
| ada.marsh@harborline.example | yes | Contracts Manager | no | `["Microsoft Authenticator push"]` | `["US"]` | - |

| IP | Known | Country | Owner | Reputation | Notes |
|---|---|---|---|---|---|
| 198.51.100.24 | yes | US | Harborline Federal VPN | benign | Always-on VPN concentrator for remote staff. |

| App ID | In catalog | Name | Publisher | Verified publisher | Sanctioned |
|---|---|---|---|---|---|
| e93b5c1d-7a40-4d2f-b8e6-0c3a91f5d274 | no | - | - | - | - |

## 4. AI assessment

Model: `claude-sonnet-5-5`. Verdict **Needs more info**, confidence **low**, severity **High**.

**Key evidence**

- Consent granted with Mail.ReadWrite (read, modify, and delete mail) plus offline_access (refresh token that outlives the browser session) on 2026-10-27T18:00:00Z, Result: success.
- App ID e93b5c1d-7a40-4d2f-b8e6-0c3a91f5d274 returned found: false in the app catalog, so the organization has no record of vetting or approving it.
- The display name 'Northwind eSign for Outlook' resembles a legitimate e-signature vendor, which fits both a genuine add-in and a brand-impersonation consent phish; the evidence cannot distinguish them.
- IsAdminConsent=False and OnBehalfOfAll=False: exposure is limited to Ada Marsh's own mailbox, not tenant-wide.
- Source IP 198.51.100.24 is the Harborline always-on VPN concentrator, reputation benign, in Ada's known_ips, and the country is within her usual (US). This argues against a foreign attacker session, but a phished user on the VPN would look the same.
- Ada's mailbox is high-value: Contracts Manager handling subcontractor agreements and CUI-marked proposal material, so exposure of her mail could mean CUI exposure under NIST SP 800-171.
- The alert contains no information on publisher verification, the app's reply URLs, how Ada reached the consent prompt (phishing email versus self-install), or any subsequent Graph API activity.

**Benign explanations considered**

- Ada installed a real e-signature add-in for Outlook to handle subcontractor agreements: plausible given her role and the VPN IP, but the app is not in the catalog and no approval record is visible.
- A sanctioned IT or contracts-team rollout of an e-sign tool: possible, but the app catalog has no entry, so there is no support for it.
- Normal user behavior from a trusted network and known IP: true for the sign-in context, but it does not validate the app itself, since a phished consent is also granted from the victim's own session.

**Recommended actions**

| Action | Target | Rationale |
|---|---|---|
| notify_user | ada.marsh@harborline.example | Ask Ada whether she knowingly installed the add-in, where she got the link or prompt (email, vendor site, Outlook store), and whether a business need exists. This is the fastest way to resolve the verdict. |
| remove_oauth_grant | e93b5c1d-7a40-4d2f-b8e6-0c3a91f5d274 (service principal 5f0d2a8c-91b3-4e67-a4d1-7c2e8b9f3a60), delegated grant for ada.marsh@harborline.example | Revoke the grant pending vetting. If the app is illicit, it holds a refresh token with read/write access to a CUI-handling mailbox, and this stops it. If legitimate, Ada can re-consent after approval, so the cost is low. |
| revoke_sessions | ada.marsh@harborline.example | Invalidate refresh tokens issued to the app along with Ada's other sessions so access does not outlive the grant removal. |

**Open questions**

- Did Ada knowingly install this add-in, and what prompted it (email link, colleague, vendor site)?
- Is 'Northwind eSign for Outlook' a vendor Harborline uses or has approved, and is the publisher verified in Entra ID?
- Did the app's service principal access Ada's mailbox via Graph (reads, sends, rules, forwarding) after 18:00:00Z?
- Did other users consent to this same app ID, and was there a related phishing email delivered to Harborline mailboxes?
- What are the app's reply URLs and tenant of origin, and was the service principal created recently?
- Were any inbox rules or forwarding settings created on Ada's mailbox around the consent time?

<details><summary>Verbatim model output</summary>

```json
{
  "verdict": "needs_more_info",
  "confidence": "low",
  "severity": "High",
  "summary": "Ada Marsh (Contracts Manager, non-admin, handles CUI-marked proposal material) consented as herself at 18:00:00Z on 2026-10-27 to 'Northwind eSign for Outlook', granting Mail.ReadWrite and offline_access (persistent refresh token). The app (client ID e93b5c1d-7a40-4d2f-b8e6-0c3a91f5d274) is not found in the organization's app catalog. The user, IP, and consent type look normal (known VPN IP, usual country, not admin consent, not tenant-wide), and a contracts manager could plausibly want an e-signature add-in. But the unvetted app, the broad mailbox read/write scope, the persistent token, and the vendor-style name (a common lure for illicit consent grants) mean the activity cannot be called benign. The evidence also cannot prove it malicious: it shows no sign-in anomaly, no post-consent mailbox activity, and no verified publisher. Treat as potentially risky until the app's legitimacy is established.",
  "timeline": [
    {
      "time": "2026-10-27T18:00:00Z",
      "event": "ada.marsh@harborline.example consented (user consent, not admin, not on behalf of all) to 'Northwind eSign for Outlook' with scopes Mail.ReadWrite, offline_access, User.Read, openid, profile, from 198.51.100.24 (Harborline VPN). Result: success."
    },
    {
      "time": "2026-10-27T18:15:00Z",
      "event": "High-privilege OAuth consent detection fired."
    }
  ],
  "key_evidence": [
    "Consent granted with Mail.ReadWrite (read, modify, and delete mail) plus offline_access (refresh token that outlives the browser session) on 2026-10-27T18:00:00Z, Result: success.",
    "App ID e93b5c1d-7a40-4d2f-b8e6-0c3a91f5d274 returned found: false in the app catalog, so the organization has no record of vetting or approving it.",
    "The display name 'Northwind eSign for Outlook' resembles a legitimate e-signature vendor, which fits both a genuine add-in and a brand-impersonation consent phish; the evidence cannot distinguish them.",
    "IsAdminConsent=False and OnBehalfOfAll=False: exposure is limited to Ada Marsh's own mailbox, not tenant-wide.",
    "Source IP 198.51.100.24 is the Harborline always-on VPN concentrator, reputation benign, in Ada's known_ips, and the country is within her usual (US). This argues against a foreign attacker session, but a phished user on the VPN would look the same.",
    "Ada's mailbox is high-value: Contracts Manager handling subcontractor agreements and CUI-marked proposal material, so exposure of her mail could mean CUI exposure under NIST SP 800-171.",
    "The alert contains no information on publisher verification, the app's reply URLs, how Ada reached the consent prompt (phishing email versus self-install), or any subsequent Graph API activity."
  ],
  "benign_explanations_considered": [
    "Ada installed a real e-signature add-in for Outlook to handle subcontractor agreements: plausible given her role and the VPN IP, but the app is not in the catalog and no approval record is visible.",
    "A sanctioned IT or contracts-team rollout of an e-sign tool: possible, but the app catalog has no entry, so there is no support for it.",
    "Normal user behavior from a trusted network and known IP: true for the sign-in context, but it does not validate the app itself, since a phished consent is also granted from the victim's own session."
  ],
  "recommended_actions": [
    {
      "action": "notify_user",
      "target": "ada.marsh@harborline.example",
      "rationale": "Ask Ada whether she knowingly installed the add-in, where she got the link or prompt (email, vendor site, Outlook store), and whether a business need exists. This is the fastest way to resolve the verdict."
    },
    {
      "action": "remove_oauth_grant",
      "target": "e93b5c1d-7a40-4d2f-b8e6-0c3a91f5d274 (service principal 5f0d2a8c-91b3-4e67-a4d1-7c2e8b9f3a60), delegated grant for ada.marsh@harborline.example",
      "rationale": "Revoke the grant pending vetting. If the app is illicit, it holds a refresh token with read/write access to a CUI-handling mailbox, and this stops it. If legitimate, Ada can re-consent after approval, so the cost is low."
    },
    {
      "action": "revoke_sessions",
      "target": "ada.marsh@harborline.example",
      "rationale": "Invalidate refresh tokens issued to the app along with Ada's other sessions so access does not outlive the grant removal."
    }
  ],
  "attack_mapping": [
    {
      "technique_id": "T1528",
      "technique_name": "Steal Application Access Token",
      "tactic": "Credential Access"
    },
    {
      "technique_id": "T1566.002",
      "technique_name": "Phishing: Spearphishing Link",
      "tactic": "Initial Access"
    },
    {
      "technique_id": "T1114.002",
      "technique_name": "Email Collection: Remote Email Collection",
      "tactic": "Collection"
    }
  ],
  "detection_tuning_notes": [
    "The rule correctly flagged a user-consented, unvetted app with Mail.ReadWrite and offline_access. Keep this combination as a high-signal trigger.",
    "Enrich with publisher verification status, app creation date, tenant of origin, and reply URLs to help separate real vendors from lookalikes.",
    "Add a correlation step that pulls MailItemsAccessed and Graph activity by the app's service principal in the hour after consent, to show whether data was read.",
    "Consider tuning severity: unknown app (not in catalog) plus mail write scope plus a CUI-handling user should score higher than the same grant to a cataloged app.",
    "Alert on first-seen app IDs across the tenant, not just per user, to catch multi-user consent campaigns."
  ],
  "open_questions": [
    "Did Ada knowingly install this add-in, and what prompted it (email link, colleague, vendor site)?",
    "Is 'Northwind eSign for Outlook' a vendor Harborline uses or has approved, and is the publisher verified in Entra ID?",
    "Did the app's service principal access Ada's mailbox via Graph (reads, sends, rules, forwarding) after 18:00:00Z?",
    "Did other users consent to this same app ID, and was there a related phishing email delivered to Harborline mailboxes?",
    "What are the app's reply URLs and tenant of origin, and was the service principal created recently?",
    "Were any inbox rules or forwarding settings created on Ada's mailbox around the consent time?"
  ]
}
```

</details>

## 5. Human decision and rationale

**Analyst:** Edward Griggs  
**Decided:** 2026-10-29T13:34:56Z  
**Verdict:** True positive (Critical)

Override. The AI stopped at needs_more_info because it could not prove the app was illegitimate. The app catalog settles it. Harborline's real e-signature vendor is Northwind eSign, app 4c1e7a52-0b9d-4f3e-8a61-2d5f9e0b7c13, verified publisher, admin-consented by IT, approved for User.Read and Files.Read only. The consented app has a different app ID, a name built to look like the sanctioned one, and asks for Mail.ReadWrite plus offline_access through user consent. A real Northwind add-in would not need Ada to consent at all, and would not need to write to her mailbox. That is an illicit consent grant: a refresh token with read and write on a CUI-handling mailbox that survives a password reset. Waiting for more information leaves that token live.

## 6. Actions

| Action | Target | Recommended by | Decision | Approver | Reason |
|---|---|---|---|---|---|
| notify_user | ada.marsh@harborline.example | AI | **approved** | Edward Griggs | Find the lure. Whatever sent her the consent link likely went to others. |
| remove_oauth_grant | e93b5c1d-7a40-4d2f-b8e6-0c3a91f5d274 (service principal 5f0d2a8c-91b3-4e67-a4d1-7c2e8b9f3a60), delegated grant for ada.marsh@harborline.example | AI | **approved** | Edward Griggs | Cut the app's access to her mailbox now. |
| revoke_sessions | ada.marsh@harborline.example | AI | **approved** | Edward Griggs | Invalidate refresh tokens issued under the grant. |
| remove_oauth_grant | service principal 5f0d2a8c-91b3-4e67-a4d1-7c2e8b9f3a60 (tenant-wide) | Analyst | **approved** | Edward Griggs | Disable and delete the service principal so no other user can consent to it. Removing one user's grant leaves the app available to the next click. |

The AI executed nothing. Approved actions are carried out by the analyst.

## 7. ATT&CK mapping

| Technique | Name | Tactic | Mapped by |
|---|---|---|---|
| [T1528](https://attack.mitre.org/techniques/T1528/) | Steal Application Access Token | Credential Access | Detection |
| [T1528](https://attack.mitre.org/techniques/T1528/) | Steal Application Access Token | Credential Access | AI |
| [T1566.002](https://attack.mitre.org/techniques/T1566/002/) | Phishing: Spearphishing Link | Initial Access | AI |
| [T1114.002](https://attack.mitre.org/techniques/T1114/002/) | Email Collection: Remote Email Collection | Collection | AI |

## 8. Detection tuning notes

Rule `1f6d8b20-7c3a-4a91-be55-3d9e0c2f8146` lives in [detection-as-code](https://github.com/edwardjgriggs/detection-as-code).

**Analyst**

- Enrichment looks apps up by exact ID only, so a lookalike scores the same as any unknown app. Add a display-name similarity check against sanctioned apps and flag a near match with a different app ID. That single field is what moved this case from 'unknown' to 'malicious'.
- Turn off user consent for apps from unverified publishers in Entra. The detection is the backstop, not the control.

**AI**

- The rule correctly flagged a user-consented, unvetted app with Mail.ReadWrite and offline_access. Keep this combination as a high-signal trigger.
- Enrich with publisher verification status, app creation date, tenant of origin, and reply URLs to help separate real vendors from lookalikes.
- Add a correlation step that pulls MailItemsAccessed and Graph activity by the app's service principal in the hour after consent, to show whether data was read.
- Consider tuning severity: unknown app (not in catalog) plus mail write scope plus a CUI-handling user should score higher than the same grant to a cataloged app.
- Alert on first-seen app IDs across the tenant, not just per user, to catch multi-user consent campaigns.
