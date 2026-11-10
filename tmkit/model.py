"""System description loaded from YAML, plus the queries the threat rules use."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml

COMPONENT_TYPES = {
    "user",
    "llm",
    "agent",
    "tool",
    "datastore",
    "vector_store",
    "retriever",
    "external_source",
    "external_api",
    "model_registry",
    "orchestrator",
}
SENSITIVITY = {"public": 1, "internal": 2, "confidential": 3, "restricted": 4}
TOOL_ACTIONS = {"read", "write", "send", "execute", "pay", "delete", "browse"}
WRITE_ACTIONS = {"write", "send", "execute", "pay", "delete"}


class ModelError(ValueError):
    pass


@dataclass
class Component:
    id: str
    type: str
    name: str = ""
    trusted: bool = True
    exposure: str = "internal"  # internal | public
    sensitivity: str = "internal"
    actions: list[str] = field(default_factory=list)  # tools only
    human_approval: bool = False  # tools only: a human approves each call
    third_party: bool = False  # hosted model / plugin / dataset from a vendor


@dataclass
class Flow:
    src: str
    dst: str
    data: str = ""
    untrusted_content: bool = False


@dataclass
class SystemModel:
    name: str
    description: str
    components: dict[str, Component]
    flows: list[Flow]
    controls_in_place: set[str]

    # ------------------------------------------------------------- queries
    def of_type(self, *types: str) -> list[Component]:
        return [c for c in self.components.values() if c.type in types]

    def has(self, *types: str) -> bool:
        return bool(self.of_type(*types))

    def public(self) -> bool:
        return any(c.exposure == "public" for c in self.components.values())

    def untrusted_into_llm(self) -> list[Flow]:
        """Flows that carry untrusted content into an LLM, agent or retriever."""
        sinks = {
            c.id for c in self.of_type("llm", "agent", "retriever", "vector_store")
        }
        out = []
        for f in self.flows:
            src = self.components[f.src]
            if src.type == "user":
                continue  # user chat is direct input, scored by T01
            if f.dst in sinks and (f.untrusted_content or not src.trusted):
                out.append(f)
        return out

    def direct_user_input(self) -> bool:
        sinks = {c.id for c in self.of_type("llm", "agent")}
        return any(
            self.components[f.src].type == "user" and f.dst in sinks for f in self.flows
        )

    def write_tools(self) -> list[Component]:
        return [c for c in self.of_type("tool") if set(c.actions) & WRITE_ACTIONS]

    def unapproved_write_tools(self) -> list[Component]:
        return [c for c in self.write_tools() if not c.human_approval]

    def max_sensitivity(self) -> int:
        stores = self.of_type("datastore", "vector_store", "tool")
        return max((SENSITIVITY[c.sensitivity] for c in stores), default=1)

    def sensitive_reachable_by_llm(self) -> bool:
        """True if an LLM/agent reads from a confidential+ store or tool."""
        llms = {c.id for c in self.of_type("llm", "agent", "retriever")}
        for f in self.flows:
            src = self.components[f.src]
            if (
                f.dst in llms
                and src.type in ("datastore", "vector_store", "tool")
                and SENSITIVITY[src.sensitivity] >= SENSITIVITY["confidential"]
            ):
                return True
        return False

    def outbound_channels(self) -> list[Component]:
        """Tools that can move data out: send, browse (URL fetch), write to external APIs."""
        return [
            c for c in self.of_type("tool") if {"send", "browse"} & set(c.actions)
        ] + self.of_type("external_api")

    def third_party(self) -> list[Component]:
        return [c for c in self.components.values() if c.third_party]


def _req(d: dict, key: str, where: str):
    if key not in d:
        raise ModelError(f"{where}: missing required field '{key}'")
    return d[key]


def parse(data: dict) -> SystemModel:
    if not isinstance(data, dict):
        raise ModelError("top level must be a mapping")
    sysd = _req(data, "system", "root")
    comps: dict[str, Component] = {}
    for i, c in enumerate(_req(data, "components", "root")):
        where = f"components[{i}]"
        cid, ctype = _req(c, "id", where), _req(c, "type", where)
        if ctype not in COMPONENT_TYPES:
            raise ModelError(f"{where}: unknown type '{ctype}'")
        if cid in comps:
            raise ModelError(f"{where}: duplicate id '{cid}'")
        sens = c.get("sensitivity", "internal")
        if sens not in SENSITIVITY:
            raise ModelError(f"{where}: unknown sensitivity '{sens}'")
        bad = set(c.get("actions", [])) - TOOL_ACTIONS
        if bad:
            raise ModelError(f"{where}: unknown actions {sorted(bad)}")
        comps[cid] = Component(
            id=cid,
            type=ctype,
            name=c.get("name", cid),
            trusted=c.get("trusted", ctype not in ("user", "external_source")),
            exposure=c.get("exposure", "internal"),
            sensitivity=sens,
            actions=list(c.get("actions", [])),
            human_approval=bool(c.get("human_approval", False)),
            third_party=bool(c.get("third_party", False)),
        )
    flows = []
    for i, f in enumerate(data.get("flows", [])):
        where = f"flows[{i}]"
        src, dst = _req(f, "from", where), _req(f, "to", where)
        for end in (src, dst):
            if end not in comps:
                raise ModelError(f"{where}: unknown component '{end}'")
        flows.append(
            Flow(src, dst, f.get("data", ""), bool(f.get("untrusted_content", False)))
        )
    return SystemModel(
        name=_req(sysd, "name", "system"),
        description=sysd.get("description", ""),
        components=comps,
        flows=flows,
        controls_in_place=set(data.get("controls_in_place", [])),
    )


def load(path: str | Path) -> SystemModel:
    return parse(yaml.safe_load(Path(path).read_text()))
