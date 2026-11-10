"""Apply the catalogue to a system model: threats, scores, residual risk, checklist."""

from __future__ import annotations

from dataclasses import asdict, dataclass

from .catalog import ATLAS, CONTROLS, OWASP_LLM_2025, STRIDE, THREATS, Threat
from .model import SystemModel

DANGEROUS = {"pay", "delete", "send", "execute"}


def rating(score: int) -> str:
    if score >= 15:
        return "Critical"
    if score >= 10:
        return "High"
    if score >= 5:
        return "Medium"
    return "Low"


@dataclass
class Finding:
    id: str
    title: str
    evidence: str
    stride: list[str]
    owasp: list[str]
    atlas: list[str]
    likelihood: int
    impact: int
    score: int
    rating: str
    residual_likelihood: int
    residual_score: int
    residual_rating: str
    mitigations_in_place: list[str]
    mitigations_missing: list[str]


def score_threat(t: Threat, m: SystemModel) -> tuple[int, int]:
    """Inherent likelihood and impact, 1..5 each.

    likelihood: +1 when the system is public; +1 for injection-driven threats
    when untrusted content reaches the model.
    impact: disclosure threats take the data sensitivity (public=1 .. restricted=4,
    +1 if restricted); action threats +1 when an unapproved tool can pay,
    delete, send or execute.
    """
    lik, imp = t.likelihood, t.impact
    if m.public():
        lik += 1
    if t.injection_driven and m.untrusted_into_llm():
        lik += 1
    if t.disclosure:
        sens = m.max_sensitivity()
        imp = max(imp, sens + (1 if sens == 4 else 0))
    if t.action and any(set(c.actions) & DANGEROUS for c in m.unapproved_write_tools()):
        imp += 1
    return min(lik, 5), min(imp, 5)


def analyse(m: SystemModel) -> list[Finding]:
    unknown = m.controls_in_place - set(CONTROLS)
    if unknown:
        raise ValueError(f"controls_in_place has unknown ids: {sorted(unknown)}")
    out = []
    for t in THREATS:
        ev = t.applies(m)
        if not ev:
            continue
        lik, imp = score_threat(t, m)
        have = [c for c in t.mitigations if c in m.controls_in_place]
        miss = [c for c in t.mitigations if c not in m.controls_in_place]
        # Each control in place cuts likelihood by one step, never below 1.
        # Impact stays: controls make the bad event rarer, not smaller.
        rlik = max(1, lik - len(have))
        out.append(
            Finding(
                id=t.id,
                title=t.title,
                evidence=ev,
                stride=[STRIDE[s] for s in t.stride],
                owasp=[f"{o} {OWASP_LLM_2025[o]}" for o in t.owasp],
                atlas=[f"{a} {ATLAS[a]}" for a in t.atlas],
                likelihood=lik,
                impact=imp,
                score=lik * imp,
                rating=rating(lik * imp),
                residual_likelihood=rlik,
                residual_score=rlik * imp,
                residual_rating=rating(rlik * imp),
                mitigations_in_place=have,
                mitigations_missing=miss,
            )
        )
    out.sort(key=lambda f: (-f.residual_score, -f.score, f.id))
    return out


def checklist(m: SystemModel, findings: list[Finding]) -> list[dict]:
    rows: dict[str, dict] = {}
    for f in findings:
        for cid in f.mitigations_in_place + f.mitigations_missing:
            c = CONTROLS[cid]
            row = rows.setdefault(
                cid,
                {
                    "id": cid,
                    "control": c.title,
                    "status": "in place" if cid in m.controls_in_place else "MISSING",
                    "addresses": [],
                    "priority_score": 0,
                    "nist_ai_rmf": list(c.nist_ai_rmf),
                    "iso27001": list(c.iso27001),
                    "soc2": list(c.soc2),
                },
            )
            row["addresses"].append(f.id)
            row["priority_score"] = max(row["priority_score"], f.score)
    return sorted(
        rows.values(),
        key=lambda r: (r["status"] != "MISSING", -r["priority_score"], r["id"]),
    )


def report(m: SystemModel) -> dict:
    findings = analyse(m)
    cl = checklist(m, findings)
    owasp_hit = sorted({o.split()[0] for f in findings for o in f.owasp})
    return {
        "system": m.name,
        "description": m.description,
        "summary": {
            "threats": len(findings),
            "inherent": {
                r: sum(f.rating == r for f in findings)
                for r in ("Critical", "High", "Medium", "Low")
            },
            "residual": {
                r: sum(f.residual_rating == r for f in findings)
                for r in ("Critical", "High", "Medium", "Low")
            },
            "inherent_total_score": sum(f.score for f in findings),
            "residual_total_score": sum(f.residual_score for f in findings),
            "controls_in_place": len([r for r in cl if r["status"] == "in place"]),
            "controls_missing": len([r for r in cl if r["status"] == "MISSING"]),
            "owasp_llm_covered": owasp_hit,
        },
        "findings": [asdict(f) for f in findings],
        "checklist": cl,
    }


def to_markdown(r: dict) -> str:
    s = r["summary"]
    L = [
        f"# Threat model: {r['system']}",
        "",
        r["description"].strip(),
        "",
        "## Summary",
        "",
        f"- Threats found: **{s['threats']}**",
        f"- Inherent: {', '.join(f'{k} {v}' for k, v in s['inherent'].items())} (total score {s['inherent_total_score']})",
        f"- Residual with listed controls: {', '.join(f'{k} {v}' for k, v in s['residual'].items())} (total score {s['residual_total_score']})",
        f"- Controls: {s['controls_in_place']} in place, {s['controls_missing']} missing",
        f"- OWASP LLM Top 10 (2025) items raised: {', '.join(s['owasp_llm_covered'])}",
        "",
        "Score = likelihood (1-5) x impact (1-5). Critical >= 15, High >= 10, Medium >= 5.",
        "",
        "## Threats",
        "",
        "| ID | Threat | STRIDE | OWASP LLM | MITRE ATLAS | L x I | Inherent | Residual | Missing controls |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for f in r["findings"]:
        L.append(
            f"| {f['id']} | {f['title']} | {', '.join(f['stride'])} | {'<br>'.join(f['owasp'])} | "
            f"{'<br>'.join(f['atlas']) or '—'} | {f['likelihood']}x{f['impact']} | {f['score']} {f['rating']} | "
            f"{f['residual_score']} {f['residual_rating']} | {', '.join(f['mitigations_missing']) or '—'} |"
        )
    L += ["", "### Evidence", ""]
    L += [f"- **{f['id']}** {f['evidence']}" for f in r["findings"]]
    L += [
        "",
        "## Control checklist",
        "",
        "| Status | ID | Control | Addresses | NIST AI RMF | ISO 27001:2022 | SOC 2 |",
        "|---|---|---|---|---|---|---|",
    ]
    for c in r["checklist"]:
        box = "[ ]" if c["status"] == "MISSING" else "[x]"
        L.append(
            f"| {box} {c['status']} | {c['id']} | {c['control']} | {', '.join(c['addresses'])} | "
            f"{', '.join(c['nist_ai_rmf'])} | {', '.join(c['iso27001']) or '— (no direct control)'} | {', '.join(c['soc2'])} |"
        )
    L += [
        "",
        "_Generated by llm-threat-model-kit. Framework mappings are engineering judgement, not an official crosswalk._",
        "",
    ]
    return "\n".join(L)
