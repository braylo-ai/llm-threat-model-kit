from __future__ import annotations

import json
from pathlib import Path

import pytest

from tmkit.__main__ import main
from tmkit.catalog import ATLAS, CONTROLS, OWASP_LLM_2025, STRIDE, THREATS
from tmkit.engine import analyse, checklist, rating, report, to_markdown
from tmkit.model import ModelError, load, parse

ROOT = Path(__file__).resolve().parents[1]
AGENCY = ROOT / "examples" / "ai-agency-stack.yaml"
RAG = ROOT / "examples" / "rag-chatbot.yaml"


def ids(findings):
    return {f.id for f in findings}


def tiny(**over):
    base = {
        "system": {"name": "tiny"},
        "components": [{"id": "u", "type": "user"}, {"id": "m", "type": "llm"}],
        "flows": [{"from": "u", "to": "m"}],
    }
    base.update(over)
    return parse(base)


# ------------------------------------------------------------- catalogue
def test_every_owasp_llm_2025_item_has_a_threat():
    covered = {o for t in THREATS for o in t.owasp}
    assert covered == set(OWASP_LLM_2025)


def test_catalogue_references_are_valid():
    for t in THREATS:
        assert t.stride and set(t.stride) <= set(STRIDE)
        assert set(t.atlas) <= set(ATLAS)
        assert t.mitigations and set(t.mitigations) <= set(CONTROLS)
        assert 1 <= t.likelihood <= 5 and 1 <= t.impact <= 5
    assert len({t.id for t in THREATS}) == len(THREATS)


def test_every_control_maps_to_nist_and_soc2():
    for c in CONTROLS.values():
        assert c.nist_ai_rmf and c.soc2, c.id
        assert all(
            x.split()[0] in {"GOVERN", "MAP", "MEASURE", "MANAGE"}
            for x in c.nist_ai_rmf
        )
        assert all(x.startswith("A.") for x in c.iso27001)


def test_every_control_is_used_by_some_threat():
    used = {m for t in THREATS for m in t.mitigations}
    assert used == set(CONTROLS)


# ----------------------------------------------------------- validation
@pytest.mark.parametrize(
    "bad,msg",
    [
        ({"components": []}, "system"),
        (
            {"system": {"name": "x"}, "components": [{"id": "a", "type": "robot"}]},
            "unknown type",
        ),
        (
            {
                "system": {"name": "x"},
                "components": [{"id": "a", "type": "llm"}, {"id": "a", "type": "llm"}],
            },
            "duplicate",
        ),
        (
            {
                "system": {"name": "x"},
                "components": [{"id": "a", "type": "llm"}],
                "flows": [{"from": "a", "to": "zz"}],
            },
            "unknown component",
        ),
        (
            {
                "system": {"name": "x"},
                "components": [{"id": "t", "type": "tool", "actions": ["teleport"]}],
            },
            "unknown actions",
        ),
        (
            {
                "system": {"name": "x"},
                "components": [
                    {"id": "d", "type": "datastore", "sensitivity": "secret"}
                ],
            },
            "sensitivity",
        ),
    ],
)
def test_schema_errors(bad, msg):
    with pytest.raises(ModelError, match=msg):
        parse(bad)


def test_unknown_control_id_rejected():
    with pytest.raises(ValueError, match="unknown ids"):
        analyse(tiny(controls_in_place=["C99"]))


# ---------------------------------------------------------------- rules
def test_minimal_chatbot_threats():
    found = ids(analyse(tiny()))
    assert {"T01", "T06", "T13"} <= found
    assert not found & {"T02", "T03", "T04", "T08", "T09", "T15"}


def test_user_chat_is_direct_not_indirect_injection():
    m = tiny()
    assert m.direct_user_input() and m.untrusted_into_llm() == []


def test_untrusted_source_triggers_indirect_injection():
    m = tiny(
        components=[
            {"id": "u", "type": "user"},
            {"id": "m", "type": "llm"},
            {"id": "web", "type": "external_source"},
        ],
        flows=[{"from": "u", "to": "m"}, {"from": "web", "to": "m"}],
    )
    assert "T02" in ids(analyse(m))


def test_human_approval_removes_excessive_agency():
    comps = [
        {"id": "a", "type": "agent"},
        {"id": "send", "type": "tool", "actions": ["send"]},
    ]
    flows = [{"from": "a", "to": "send"}]
    assert "T03" in ids(analyse(tiny(components=comps, flows=flows)))
    comps[1]["human_approval"] = True
    assert "T03" not in ids(analyse(tiny(components=comps, flows=flows)))


def test_read_only_tools_are_not_excessive_agency():
    comps = [
        {"id": "a", "type": "agent"},
        {"id": "r", "type": "tool", "actions": ["read"]},
    ]
    assert "T03" not in ids(
        analyse(tiny(components=comps, flows=[{"from": "r", "to": "a"}]))
    )


# -------------------------------------------------------------- scoring
def test_rating_bands():
    assert [rating(s) for s in (25, 15, 14, 10, 9, 5, 4, 1)] == [
        "Critical",
        "Critical",
        "High",
        "High",
        "Medium",
        "Medium",
        "Low",
        "Low",
    ]


def test_public_exposure_raises_likelihood():
    internal = {f.id: f for f in analyse(tiny())}
    public = {
        f.id: f
        for f in analyse(
            tiny(
                components=[
                    {"id": "u", "type": "user", "exposure": "public"},
                    {"id": "m", "type": "llm"},
                ]
            )
        )
    }
    assert public["T01"].likelihood == internal["T01"].likelihood + 1


def test_controls_reduce_residual_never_below_one_or_impact():
    none = {f.id: f for f in analyse(tiny())}
    full = {
        f.id: f for f in analyse(tiny(controls_in_place=["C01", "C08", "C03", "C14"]))
    }
    assert full["T01"].residual_score < none["T01"].residual_score
    assert full["T01"].residual_likelihood == 1
    assert full["T01"].impact == none["T01"].impact
    assert none["T01"].residual_score == none["T01"].score


def test_restricted_data_maxes_disclosure_impact():
    comps = [
        {"id": "u", "type": "user"},
        {"id": "m", "type": "llm"},
        {"id": "d", "type": "datastore", "sensitivity": "restricted"},
    ]
    f = {
        x.id: x
        for x in analyse(
            tiny(
                components=comps,
                flows=[{"from": "u", "to": "m"}, {"from": "d", "to": "m"}],
            )
        )
    }
    assert f["T05"].impact == 5


# ------------------------------------------------------------- examples
def test_agency_example_flags_injection_exfil_and_agency_as_critical():
    f = {x.id: x for x in analyse(load(AGENCY))}
    for tid in ("T02", "T04", "T03"):
        assert f[tid].rating == "Critical", tid
    assert "T08" not in f  # no vector store in this stack


def test_rag_example_flags_poisoning_and_acl():
    f = {x.id: x for x in analyse(load(RAG))}
    assert {"T08", "T09", "T11", "T12"} <= set(f)
    assert "T03" not in f  # chatbot has no write tools


def test_checklist_puts_missing_first_and_marks_in_place():
    m = load(AGENCY)
    cl = checklist(m, analyse(m))
    statuses = [r["status"] for r in cl]
    assert statuses == sorted(statuses, key=lambda s: s != "MISSING")
    assert {r["id"] for r in cl if r["status"] == "in place"} == {"C08", "C13", "C17"}


def test_report_is_deterministic_and_markdown_has_all_threats():
    a, b = report(load(RAG)), report(load(RAG))
    assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)
    md = to_markdown(a)
    for f in a["findings"]:
        assert f"| {f['id']} |" in md


def test_committed_reports_match_current_engine():
    for ex in (AGENCY, RAG, ROOT / "examples" / "ai-agency-stack-hardened.yaml"):
        committed = json.loads((ROOT / "reports" / f"{ex.stem}.json").read_text())
        assert committed == json.loads(json.dumps(report(load(ex)))), ex.stem


# ------------------------------------------------------------------ CLI
def test_cli_writes_files_and_fail_on(tmp_path):
    assert main([str(RAG), "-o", str(tmp_path)]) == 0
    assert (tmp_path / "rag-chatbot.md").exists() and (
        tmp_path / "rag-chatbot.json"
    ).exists()
    assert main([str(RAG), "-o", str(tmp_path), "--fail-on", "Critical"]) == 1


def test_cli_bad_input_exit_2(tmp_path):
    p = tmp_path / "bad.yaml"
    p.write_text("system: {name: x}\ncomponents: [{id: a, type: robot}]\n")
    assert main([str(p)]) == 2
