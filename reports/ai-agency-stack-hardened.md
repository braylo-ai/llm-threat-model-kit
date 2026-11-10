# Threat model: AI agency client-ops agents

An orchestrator routes inbound client email to a triage agent. The agent reads the email, looks up the client in the CRM, updates the deal record, drafts a reply and sends it, and can create calendar invites. A hosted third-party LLM API powers all agents. Staff use an internal chat UI to give the agents ad-hoc instructions.

## Summary

- Threats found: **12**
- Inherent: Critical 5, High 1, Medium 6, Low 0 (total score 148)
- Residual with listed controls: Critical 0, High 1, Medium 8, Low 3 (total score 73)
- Controls: 9 in place, 7 missing
- OWASP LLM Top 10 (2025) items raised: LLM01, LLM02, LLM03, LLM05, LLM06, LLM07, LLM09, LLM10

Score = likelihood (1-5) x impact (1-5). Critical >= 15, High >= 10, Medium >= 5.

## Threats

| ID | Threat | STRIDE | OWASP LLM | MITRE ATLAS | L x I | Inherent | Residual | Missing controls |
|---|---|---|---|---|---|---|---|---|
| T02 | Indirect prompt injection through untrusted content | Tampering, Elevation of privilege | LLM01 Prompt Injection | AML.T0051.001 LLM Prompt Injection: Indirect | 5x5 | 25 Critical | 10 High | C01 |
| T01 | Direct prompt injection / jailbreak | Tampering, Elevation of privilege | LLM01 Prompt Injection | AML.T0051.000 LLM Prompt Injection: Direct<br>AML.T0054 LLM Jailbreak | 5x3 | 15 Critical | 9 Medium | C01, C14 |
| T13 | Misinformation or hallucinated actions | Tampering | LLM09 Misinformation | AML.T0048 External Harms | 3x3 | 9 Medium | 9 Medium | C15, C14 |
| T10 | Supply-chain compromise of model, plugin or dataset | Tampering | LLM03 Supply Chain | AML.T0010 ML Supply Chain Compromise | 2x4 | 8 Medium | 8 Medium | C11, C14 |
| T15 | No audit trail for agent decisions | Repudiation | LLM06 Excessive Agency | — | 3x3 | 9 Medium | 6 Medium | C16 |
| T06 | System prompt leakage | Information disclosure | LLM07 System Prompt Leakage | AML.T0056 LLM Meta Prompt Extraction | 4x2 | 8 Medium | 6 Medium | C01 |
| T03 | Excessive agency: high-impact tool calls without approval | Elevation of privilege, Repudiation | LLM06 Excessive Agency | AML.T0053 LLM Plugin Compromise | 3x5 | 15 Critical | 5 Medium | C12 |
| T07 | Improper output handling in downstream systems | Tampering, Elevation of privilege | LLM05 Improper Output Handling | AML.T0050 Command and Scripting Interpreter | 3x5 | 15 Critical | 5 Medium | — |
| T14 | Agent acts under a shared, over-privileged identity | Spoofing, Repudiation | LLM06 Excessive Agency | AML.T0012 Valid Accounts | 2x5 | 10 High | 5 Medium | — |
| T04 | Data exfiltration through outbound tools or rendered links | Information disclosure | LLM02 Sensitive Information Disclosure<br>LLM05 Improper Output Handling | AML.T0057 LLM Data Leakage | 4x4 | 16 Critical | 4 Low | — |
| T05 | Sensitive information disclosure in responses | Information disclosure | LLM02 Sensitive Information Disclosure | AML.T0057 LLM Data Leakage | 3x3 | 9 Medium | 3 Low | C09 |
| T12 | Unbounded consumption / denial of wallet | Denial of service | LLM10 Unbounded Consumption | AML.T0029 Denial of ML Service<br>AML.T0034 Cost Harvesting | 3x3 | 9 Medium | 3 Low | C12 |

### Evidence

- **T02** untrusted content flows into the model: orchestrator->triage_agent
- **T01** users send free text straight to the model
- **T13** model output reaches people or systems
- **T10** third-party components: llm_api
- **T15** agent takes multi-step decisions
- **T06** system prompt is reachable through user chat
- **T03** write/send tools without human approval: calendar, crm_write, email_send
- **T07** model output drives downstream systems: calendar, crm_write
- **T14** agent acts on other systems through: calendar, crm_write, email_send
- **T04** model reads confidential data and can reach outbound channels: email_send
- **T05** model reads confidential or restricted data
- **T12** autonomous agent loop

## Control checklist

| Status | ID | Control | Addresses | NIST AI RMF | ISO 27001:2022 | SOC 2 |
|---|---|---|---|---|---|---|
| [ ] MISSING | C01 | Prompt-injection and jailbreak detection on model inputs | T02, T01, T06 | MEASURE 2.7 | A.8.26, A.8.29 | CC6.8, CC7.2 |
| [ ] MISSING | C12 | Rate limits, token/cost budgets and step limits for agent loops | T03, T12 | MEASURE 2.4, MANAGE 2.4 | A.8.6 | A1.1 |
| [ ] MISSING | C14 | Adversarial / red-team evaluation before release and on every model change | T01, T13, T10 | MEASURE 1.1, MEASURE 2.7 | A.8.29, A.8.32 | CC7.1, CC8.1 |
| [ ] MISSING | C09 | Document-level access control enforced at retrieval time | T05 | MEASURE 2.10, MANAGE 1.3 | A.5.15, A.8.3 | CC6.1, C1.1 |
| [ ] MISSING | C15 | Grounding and citation checks; human review of consequential outputs | T13 | MEASURE 2.5, MANAGE 4.1 | — (no direct control) | PI1.3 |
| [ ] MISSING | C16 | AI incident response plan with a kill switch for agent features | T15 | MANAGE 2.4, MANAGE 4.3 | A.5.24, A.5.26 | CC7.4 |
| [ ] MISSING | C11 | Supplier and model provenance review: pinned versions, model cards, AI-BOM | T10 | GOVERN 6.1, MAP 4.1, MANAGE 3.1, MANAGE 3.2 | A.5.19, A.5.21, A.5.23 | CC9.2 |
| [x] in place | C02 | Isolate untrusted content: delimit/spotlight it, never follow instructions found in data | T02, T04 | MEASURE 2.7, MANAGE 1.3 | A.8.27, A.8.28 | CC6.6 |
| [x] in place | C03 | Least-privilege tool scopes with per-user delegated credentials | T02, T01, T03, T07, T14 | MANAGE 1.3, MEASURE 2.7 | A.5.15, A.5.18, A.8.2, A.8.3 | CC6.1, CC6.3 |
| [x] in place | C04 | Human approval for high-impact actions (send, pay, delete, external write) | T02, T03, T04 | MAP 3.5, GOVERN 3.2 | A.5.3, A.8.2 | CC6.3, CC5.2 |
| [x] in place | C06 | Egress allow-list; strip external links/images from rendered output | T04 | MEASURE 2.7 | A.8.12, A.8.20, A.8.23 | CC6.7 |
| [x] in place | C07 | Data minimisation and PII redaction before data enters model context | T04, T05 | MEASURE 2.10 | A.5.34, A.8.11, A.8.12 | C1.1, CC6.7 |
| [x] in place | C05 | Validate and encode model output before SQL, shell, HTML or API use | T07 | MEASURE 2.7 | A.8.26, A.8.28 | CC6.8, PI1.3 |
| [x] in place | C08 | No secrets or access logic in system prompts; secrets in a vault | T01, T06 | MEASURE 2.7 | A.5.17 | CC6.1 |
| [x] in place | C13 | Tamper-evident logs of prompts, retrievals, tool calls and approvals | T15, T03, T14, T12 | MEASURE 2.4, MANAGE 4.1 | A.8.15, A.8.16 | CC7.2, CC7.3 |
| [x] in place | C17 | Strong authentication and tenant isolation on the chat/API surface | T14, T05, T12 | MEASURE 2.7 | A.5.16, A.8.5 | CC6.1, CC6.2 |

_Generated by llm-threat-model-kit. Framework mappings are engineering judgement, not an official crosswalk._
