# Threat model: Public RAG support chatbot

Anonymous website visitors ask product questions. A retriever pulls chunks from a vector store built from public docs and an internal support knowledge base (which holds some customer case notes). A self-hosted fine-tuned model answers with citations. A nightly job indexes new docs and community forum posts.

## Summary

- Threats found: **10**
- Inherent: Critical 3, High 7, Medium 0, Low 0 (total score 132)
- Residual with listed controls: Critical 2, High 2, Medium 6, Low 0 (total score 103)
- Controls: 4 in place, 11 missing
- OWASP LLM Top 10 (2025) items raised: LLM01, LLM02, LLM03, LLM04, LLM07, LLM08, LLM09, LLM10

Score = likelihood (1-5) x impact (1-5). Critical >= 15, High >= 10, Medium >= 5.

## Threats

| ID | Threat | STRIDE | OWASP LLM | MITRE ATLAS | L x I | Inherent | Residual | Missing controls |
|---|---|---|---|---|---|---|---|---|
| T02 | Indirect prompt injection through untrusted content | Tampering, Elevation of privilege | LLM01 Prompt Injection | AML.T0051.001 LLM Prompt Injection: Indirect | 5x4 | 20 Critical | 16 Critical | C02, C04, C03 |
| T08 | RAG / vector store poisoning | Tampering | LLM04 Data and Model Poisoning<br>LLM08 Vector and Embedding Weaknesses | AML.T0070 RAG Poisoning | 5x3 | 15 Critical | 15 Critical | C10, C02, C09 |
| T05 | Sensitive information disclosure in responses | Information disclosure | LLM02 Sensitive Information Disclosure | AML.T0057 LLM Data Leakage | 4x3 | 12 High | 12 High | C07, C09, C17 |
| T09 | Retrieval access-control bypass | Information disclosure | LLM08 Vector and Embedding Weaknesses<br>LLM02 Sensitive Information Disclosure | AML.T0057 LLM Data Leakage | 4x3 | 12 High | 12 High | C09, C18 |
| T01 | Direct prompt injection / jailbreak | Tampering, Elevation of privilege | LLM01 Prompt Injection | AML.T0051.000 LLM Prompt Injection: Direct<br>AML.T0054 LLM Jailbreak | 5x3 | 15 Critical | 9 Medium | C08, C03 |
| T12 | Unbounded consumption / denial of wallet | Denial of service | LLM10 Unbounded Consumption | AML.T0029 Denial of ML Service<br>AML.T0034 Cost Harvesting | 4x3 | 12 High | 9 Medium | C17, C13 |
| T10 | Supply-chain compromise of model, plugin or dataset | Tampering | LLM03 Supply Chain | AML.T0010 ML Supply Chain Compromise | 3x4 | 12 High | 8 Medium | C11 |
| T11 | Training / fine-tune data poisoning | Tampering | LLM04 Data and Model Poisoning | AML.T0020 Poison Training Data | 3x4 | 12 High | 8 Medium | C10, C11 |
| T06 | System prompt leakage | Information disclosure | LLM07 System Prompt Leakage | AML.T0056 LLM Meta Prompt Extraction | 5x2 | 10 High | 8 Medium | C08 |
| T13 | Misinformation or hallucinated actions | Tampering | LLM09 Misinformation | AML.T0048 External Harms | 4x3 | 12 High | 6 Medium | — |

### Evidence

- **T02** untrusted content flows into the model: forum->vectors
- **T08** untrusted content is indexed: forum->vectors
- **T05** model reads confidential or restricted data
- **T09** vector store holds confidential data: vectors
- **T01** users send free text straight to the model
- **T12** public endpoint
- **T10** third-party components: base_model
- **T11** fine-tuned or self-hosted models: base_model, registry
- **T06** system prompt is reachable through user chat
- **T13** model output reaches people or systems

## Control checklist

| Status | ID | Control | Addresses | NIST AI RMF | ISO 27001:2022 | SOC 2 |
|---|---|---|---|---|---|---|
| [ ] MISSING | C02 | Isolate untrusted content: delimit/spotlight it, never follow instructions found in data | T02, T08 | MEASURE 2.7, MANAGE 1.3 | A.8.27, A.8.28 | CC6.6 |
| [ ] MISSING | C03 | Least-privilege tool scopes with per-user delegated credentials | T02, T01 | MANAGE 1.3, MEASURE 2.7 | A.5.15, A.5.18, A.8.2, A.8.3 | CC6.1, CC6.3 |
| [ ] MISSING | C04 | Human approval for high-impact actions (send, pay, delete, external write) | T02 | MAP 3.5, GOVERN 3.2 | A.5.3, A.8.2 | CC6.3, CC5.2 |
| [ ] MISSING | C08 | No secrets or access logic in system prompts; secrets in a vault | T01, T06 | MEASURE 2.7 | A.5.17 | CC6.1 |
| [ ] MISSING | C09 | Document-level access control enforced at retrieval time | T08, T05, T09 | MEASURE 2.10, MANAGE 1.3 | A.5.15, A.8.3 | CC6.1, C1.1 |
| [ ] MISSING | C10 | Vet and record provenance of ingested / training content | T08, T11 | MAP 4.2, MEASURE 2.7 | A.5.21, A.8.25 | CC7.1 |
| [ ] MISSING | C07 | Data minimisation and PII redaction before data enters model context | T05 | MEASURE 2.10 | A.5.34, A.8.11, A.8.12 | C1.1, CC6.7 |
| [ ] MISSING | C11 | Supplier and model provenance review: pinned versions, model cards, AI-BOM | T10, T11 | GOVERN 6.1, MAP 4.1, MANAGE 3.1, MANAGE 3.2 | A.5.19, A.5.21, A.5.23 | CC9.2 |
| [ ] MISSING | C13 | Tamper-evident logs of prompts, retrievals, tool calls and approvals | T12 | MEASURE 2.4, MANAGE 4.1 | A.8.15, A.8.16 | CC7.2, CC7.3 |
| [ ] MISSING | C17 | Strong authentication and tenant isolation on the chat/API surface | T05, T12 | MEASURE 2.7 | A.5.16, A.8.5 | CC6.1, CC6.2 |
| [ ] MISSING | C18 | Harden the vector store: tenant partitions, encryption, no raw-embedding export | T09 | MEASURE 2.10 | A.8.3, A.8.24 | CC6.1, C1.1 |
| [x] in place | C01 | Prompt-injection and jailbreak detection on model inputs | T02, T01, T06 | MEASURE 2.7 | A.8.26, A.8.29 | CC6.8, CC7.2 |
| [x] in place | C14 | Adversarial / red-team evaluation before release and on every model change | T01, T10, T11, T13 | MEASURE 1.1, MEASURE 2.7 | A.8.29, A.8.32 | CC7.1, CC8.1 |
| [x] in place | C12 | Rate limits, token/cost budgets and step limits for agent loops | T12 | MEASURE 2.4, MANAGE 2.4 | A.8.6 | A1.1 |
| [x] in place | C15 | Grounding and citation checks; human review of consequential outputs | T13 | MEASURE 2.5, MANAGE 4.1 | — (no direct control) | PI1.3 |

_Generated by llm-threat-model-kit. Framework mappings are engineering judgement, not an official crosswalk._
