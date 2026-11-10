"""Threat and control catalogue.

Framework references:
* OWASP Top 10 for LLM Applications, 2025 edition (LLM01..LLM10).
* MITRE ATLAS technique ids (AML.Txxxx).
* STRIDE categories.
* NIST AI RMF 1.0 subcategories (GOVERN / MAP / MEASURE / MANAGE).
* ISO/IEC 27001:2022 Annex A controls.
* AICPA SOC 2 Trust Services Criteria (2017, revised points of focus 2022).

The mappings are an engineer's judgement, not an official crosswalk. An empty
list means no control in that framework addresses the item directly.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from .model import SENSITIVITY, SystemModel

OWASP_LLM_2025 = {
    "LLM01": "Prompt Injection",
    "LLM02": "Sensitive Information Disclosure",
    "LLM03": "Supply Chain",
    "LLM04": "Data and Model Poisoning",
    "LLM05": "Improper Output Handling",
    "LLM06": "Excessive Agency",
    "LLM07": "System Prompt Leakage",
    "LLM08": "Vector and Embedding Weaknesses",
    "LLM09": "Misinformation",
    "LLM10": "Unbounded Consumption",
}

ATLAS = {
    "AML.T0010": "ML Supply Chain Compromise",
    "AML.T0012": "Valid Accounts",
    "AML.T0020": "Poison Training Data",
    "AML.T0029": "Denial of ML Service",
    "AML.T0034": "Cost Harvesting",
    "AML.T0048": "External Harms",
    "AML.T0050": "Command and Scripting Interpreter",
    "AML.T0051.000": "LLM Prompt Injection: Direct",
    "AML.T0051.001": "LLM Prompt Injection: Indirect",
    "AML.T0053": "LLM Plugin Compromise",
    "AML.T0054": "LLM Jailbreak",
    "AML.T0056": "LLM Meta Prompt Extraction",
    "AML.T0057": "LLM Data Leakage",
    "AML.T0070": "RAG Poisoning",
}

STRIDE = {
    "S": "Spoofing",
    "T": "Tampering",
    "R": "Repudiation",
    "I": "Information disclosure",
    "D": "Denial of service",
    "E": "Elevation of privilege",
}


@dataclass(frozen=True)
class Control:
    id: str
    title: str
    nist_ai_rmf: tuple[str, ...]
    iso27001: tuple[str, ...]
    soc2: tuple[str, ...]


CONTROLS: dict[str, Control] = {
    c.id: c
    for c in [
        Control(
            "C01",
            "Prompt-injection and jailbreak detection on model inputs",
            ("MEASURE 2.7",),
            ("A.8.26", "A.8.29"),
            ("CC6.8", "CC7.2"),
        ),
        Control(
            "C02",
            "Isolate untrusted content: delimit/spotlight it, never follow instructions found in data",
            ("MEASURE 2.7", "MANAGE 1.3"),
            ("A.8.27", "A.8.28"),
            ("CC6.6",),
        ),
        Control(
            "C03",
            "Least-privilege tool scopes with per-user delegated credentials",
            ("MANAGE 1.3", "MEASURE 2.7"),
            ("A.5.15", "A.5.18", "A.8.2", "A.8.3"),
            ("CC6.1", "CC6.3"),
        ),
        Control(
            "C04",
            "Human approval for high-impact actions (send, pay, delete, external write)",
            ("MAP 3.5", "GOVERN 3.2"),
            ("A.5.3", "A.8.2"),
            ("CC6.3", "CC5.2"),
        ),
        Control(
            "C05",
            "Validate and encode model output before SQL, shell, HTML or API use",
            ("MEASURE 2.7",),
            ("A.8.26", "A.8.28"),
            ("CC6.8", "PI1.3"),
        ),
        Control(
            "C06",
            "Egress allow-list; strip external links/images from rendered output",
            ("MEASURE 2.7",),
            ("A.8.12", "A.8.20", "A.8.23"),
            ("CC6.7",),
        ),
        Control(
            "C07",
            "Data minimisation and PII redaction before data enters model context",
            ("MEASURE 2.10",),
            ("A.5.34", "A.8.11", "A.8.12"),
            ("C1.1", "CC6.7"),
        ),
        Control(
            "C08",
            "No secrets or access logic in system prompts; secrets in a vault",
            ("MEASURE 2.7",),
            ("A.5.17",),
            ("CC6.1",),
        ),
        Control(
            "C09",
            "Document-level access control enforced at retrieval time",
            ("MEASURE 2.10", "MANAGE 1.3"),
            ("A.5.15", "A.8.3"),
            ("CC6.1", "C1.1"),
        ),
        Control(
            "C10",
            "Vet and record provenance of ingested / training content",
            ("MAP 4.2", "MEASURE 2.7"),
            ("A.5.21", "A.8.25"),
            ("CC7.1",),
        ),
        Control(
            "C11",
            "Supplier and model provenance review: pinned versions, model cards, AI-BOM",
            ("GOVERN 6.1", "MAP 4.1", "MANAGE 3.1", "MANAGE 3.2"),
            ("A.5.19", "A.5.21", "A.5.23"),
            ("CC9.2",),
        ),
        Control(
            "C12",
            "Rate limits, token/cost budgets and step limits for agent loops",
            ("MEASURE 2.4", "MANAGE 2.4"),
            ("A.8.6",),
            ("A1.1",),
        ),
        Control(
            "C13",
            "Tamper-evident logs of prompts, retrievals, tool calls and approvals",
            ("MEASURE 2.4", "MANAGE 4.1"),
            ("A.8.15", "A.8.16"),
            ("CC7.2", "CC7.3"),
        ),
        Control(
            "C14",
            "Adversarial / red-team evaluation before release and on every model change",
            ("MEASURE 1.1", "MEASURE 2.7"),
            ("A.8.29", "A.8.32"),
            ("CC7.1", "CC8.1"),
        ),
        Control(
            "C15",
            "Grounding and citation checks; human review of consequential outputs",
            ("MEASURE 2.5", "MANAGE 4.1"),
            (),
            ("PI1.3",),
        ),
        Control(
            "C16",
            "AI incident response plan with a kill switch for agent features",
            ("MANAGE 2.4", "MANAGE 4.3"),
            ("A.5.24", "A.5.26"),
            ("CC7.4",),
        ),
        Control(
            "C17",
            "Strong authentication and tenant isolation on the chat/API surface",
            ("MEASURE 2.7",),
            ("A.5.16", "A.8.5"),
            ("CC6.1", "CC6.2"),
        ),
        Control(
            "C18",
            "Harden the vector store: tenant partitions, encryption, no raw-embedding export",
            ("MEASURE 2.10",),
            ("A.8.3", "A.8.24"),
            ("CC6.1", "C1.1"),
        ),
    ]
}


Evidence = Callable[[SystemModel], "str | None"]


@dataclass(frozen=True)
class Threat:
    id: str
    title: str
    stride: tuple[str, ...]
    owasp: tuple[str, ...]
    atlas: tuple[str, ...]
    likelihood: int  # base 1..5
    impact: int  # base 1..5
    mitigations: tuple[str, ...]
    applies: Evidence
    injection_driven: bool = False  # likelihood rises with untrusted input
    disclosure: bool = False  # impact follows data sensitivity
    action: bool = False  # impact rises with dangerous unapproved tools


def _names(cs) -> str:
    return ", ".join(sorted(c.id for c in cs))


def _direct(m: SystemModel):
    return (
        "users send free text straight to the model" if m.direct_user_input() else None
    )


def _indirect(m: SystemModel):
    fl = m.untrusted_into_llm()
    return (
        f"untrusted content flows into the model: {', '.join(f'{f.src}->{f.dst}' for f in fl)}"
        if fl
        else None
    )


def _agency(m: SystemModel):
    t = m.unapproved_write_tools()
    return f"write/send tools without human approval: {_names(t)}" if t else None


def _exfil(m: SystemModel):
    out = m.outbound_channels()
    if (
        m.sensitive_reachable_by_llm()
        and out
        and (m.untrusted_into_llm() or m.direct_user_input())
    ):
        return f"model reads confidential data and can reach outbound channels: {_names(out)}"
    return None


def _disclosure(m: SystemModel):
    return (
        "model reads confidential or restricted data"
        if m.sensitive_reachable_by_llm()
        else None
    )


def _prompt_leak(m: SystemModel):
    return (
        "system prompt is reachable through user chat"
        if m.has("llm", "agent") and m.direct_user_input()
        else None
    )


def _output_handling(m: SystemModel):
    t = [
        c for c in m.of_type("tool") if {"execute", "write"} & set(c.actions)
    ] + m.of_type("external_api")
    return f"model output drives downstream systems: {_names(t)}" if t else None


def _rag_poison(m: SystemModel):
    stores = {c.id for c in m.of_type("vector_store")}
    bad = [
        f
        for f in m.flows
        if f.dst in stores and (f.untrusted_content or not m.components[f.src].trusted)
    ]
    if bad:
        return f"untrusted content is indexed: {', '.join(f'{f.src}->{f.dst}' for f in bad)}"
    return None


def _rag_acl(m: SystemModel):
    vs = [
        c
        for c in m.of_type("vector_store")
        if SENSITIVITY[c.sensitivity] >= SENSITIVITY["confidential"]
    ]
    return f"vector store holds confidential data: {_names(vs)}" if vs else None


def _supply(m: SystemModel):
    t = m.third_party()
    return f"third-party components: {_names(t)}" if t else None


def _poison(m: SystemModel):
    r = m.of_type("model_registry")
    return f"fine-tuned or self-hosted models: {_names(r)}" if r else None


def _consumption(m: SystemModel):
    if m.public():
        return "public endpoint"
    if m.has("agent"):
        return "autonomous agent loop"
    return None


def _misinfo(m: SystemModel):
    return "model output reaches people or systems" if m.has("llm", "agent") else None


def _identity(m: SystemModel):
    t = m.write_tools()
    return (
        f"agent acts on other systems through: {_names(t)}"
        if t and m.has("agent")
        else None
    )


def _audit(m: SystemModel):
    return "agent takes multi-step decisions" if m.has("agent") else None


THREATS: list[Threat] = [
    Threat(
        "T01",
        "Direct prompt injection / jailbreak",
        ("T", "E"),
        ("LLM01",),
        ("AML.T0051.000", "AML.T0054"),
        4,
        3,
        ("C01", "C08", "C03", "C14"),
        _direct,
        injection_driven=True,
    ),
    Threat(
        "T02",
        "Indirect prompt injection through untrusted content",
        ("T", "E"),
        ("LLM01",),
        ("AML.T0051.001",),
        4,
        4,
        ("C02", "C01", "C04", "C03"),
        _indirect,
        injection_driven=True,
        action=True,
    ),
    Threat(
        "T03",
        "Excessive agency: high-impact tool calls without approval",
        ("E", "R"),
        ("LLM06",),
        ("AML.T0053",),
        3,
        4,
        ("C04", "C03", "C13", "C12"),
        _agency,
        action=True,
    ),
    Threat(
        "T04",
        "Data exfiltration through outbound tools or rendered links",
        ("I",),
        ("LLM02", "LLM05"),
        ("AML.T0057",),
        3,
        4,
        ("C06", "C04", "C07", "C02"),
        _exfil,
        injection_driven=True,
        disclosure=True,
    ),
    Threat(
        "T05",
        "Sensitive information disclosure in responses",
        ("I",),
        ("LLM02",),
        ("AML.T0057",),
        3,
        3,
        ("C07", "C09", "C17"),
        _disclosure,
        disclosure=True,
    ),
    Threat(
        "T06",
        "System prompt leakage",
        ("I",),
        ("LLM07",),
        ("AML.T0056",),
        4,
        2,
        ("C08", "C01"),
        _prompt_leak,
    ),
    Threat(
        "T07",
        "Improper output handling in downstream systems",
        ("T", "E"),
        ("LLM05",),
        ("AML.T0050",),
        3,
        4,
        ("C05", "C03"),
        _output_handling,
        action=True,
    ),
    Threat(
        "T08",
        "RAG / vector store poisoning",
        ("T",),
        ("LLM04", "LLM08"),
        ("AML.T0070",),
        3,
        3,
        ("C10", "C02", "C09"),
        _rag_poison,
        injection_driven=True,
    ),
    Threat(
        "T09",
        "Retrieval access-control bypass",
        ("I",),
        ("LLM08", "LLM02"),
        ("AML.T0057",),
        3,
        3,
        ("C09", "C18"),
        _rag_acl,
        disclosure=True,
    ),
    Threat(
        "T10",
        "Supply-chain compromise of model, plugin or dataset",
        ("T",),
        ("LLM03",),
        ("AML.T0010",),
        2,
        4,
        ("C11", "C14"),
        _supply,
    ),
    Threat(
        "T11",
        "Training / fine-tune data poisoning",
        ("T",),
        ("LLM04",),
        ("AML.T0020",),
        2,
        4,
        ("C10", "C11", "C14"),
        _poison,
    ),
    Threat(
        "T12",
        "Unbounded consumption / denial of wallet",
        ("D",),
        ("LLM10",),
        ("AML.T0029", "AML.T0034"),
        3,
        3,
        ("C12", "C17", "C13"),
        _consumption,
    ),
    Threat(
        "T13",
        "Misinformation or hallucinated actions",
        ("T",),
        ("LLM09",),
        ("AML.T0048",),
        3,
        3,
        ("C15", "C14"),
        _misinfo,
    ),
    Threat(
        "T14",
        "Agent acts under a shared, over-privileged identity",
        ("S", "R"),
        ("LLM06",),
        ("AML.T0012",),
        2,
        4,
        ("C03", "C13", "C17"),
        _identity,
        action=True,
    ),
    Threat(
        "T15",
        "No audit trail for agent decisions",
        ("R",),
        ("LLM06",),
        (),
        3,
        3,
        ("C13", "C16"),
        _audit,
    ),
]
