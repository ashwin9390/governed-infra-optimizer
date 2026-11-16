"""
Unified optimizer core.
One tamper-evident Decision Record per change ties together cost, carbon,
performance (SLO), security, approval and recovery.

Run the built-in self-test:  python optimizer_core.py
Replace SimConnector with real connectors (cloud APIs, Terraform, K8s).
"""
from __future__ import annotations
import copy, hashlib, hmac, json, time
from fnmatch import fnmatch
from dataclasses import dataclass, field
from enum import Enum


SCHEMA_VERSION = "dr/0.1"


class Domain(Enum):                 # Cynefin class -> default autonomy
    CLEAR = "clear"                 # auto-apply when safe
    COMPLICATED = "complicated"     # recommend + human approval
    COMPLEX = "complex"             # canary + human approval


class Mode(Enum):                   # the learn switch
    OFF = "off"                     # no learning, recommend-only
    LEARN = "learn"                 # collect baselines, recommend-only
    SHADOW = "shadow"               # evaluate like ACTIVE but never apply; reconcile later
    ACTIVE = "active"               # may apply, using learned baselines


class Verdict(Enum):
    AUTO = "auto"
    NEEDS_APPROVAL = "needs_approval"
    RECOMMEND = "recommend"
    BLOCKED = "blocked"
    SHADOW = "shadow"


@dataclass
class Resource:
    id: str
    owner: str                      # RACI: accountable owner
    region: str
    monthly_cost: float
    monthly_kg_co2: float
    slo_headroom: float = 0.5       # 0..1 spare capacity vs SLO
    stateful: bool = False
    config: dict = field(default_factory=dict)


@dataclass
class Proposal:
    resource_id: str
    action: str
    domain: Domain
    d_cost: float                   # predicted change, negative = saving
    d_co2: float
    slo_risk: float                 # 0..1
    reversible: bool = True
    new_region: str | None = None
    new_config: dict = field(default_factory=dict)
    co2_range: tuple[float, float] | None = None   # (low, high) of d_co2 when uncertain


@dataclass
class Policy:
    allowed_regions: set
    max_slo_risk: float = 0.2
    min_headroom: float = 0.15
    max_changes_per_window: int = 3
    carbon_price_per_kg: float = 0.0    # currency value of 1 kg CO2
    promote_after: int = 3              # clean applies before autonomy is earned
    max_pred_error: float = 0.25        # allowed |realized - predicted| / |predicted|

    @classmethod
    def from_dict(cls, d: dict) -> "Policy":
        d = dict(d)
        d["allowed_regions"] = set(d["allowed_regions"])
        return cls(**d)


class Ledger:
    """Hash-chained, append-only record of every decision."""

    def __init__(self, signing_key: bytes | None = None):
        self.records: list[dict] = []
        self.key = signing_key          # optional HMAC key: records become signed

    @staticmethod
    def _hash(body: dict) -> str:
        return hashlib.sha256(json.dumps(body, sort_keys=True, default=str).encode()).hexdigest()

    def append(self, data: dict) -> dict:
        prev = self.records[-1]["hash"] if self.records else "0" * 64
        body = {"ts": time.time(), "prev": prev, "data": data}
        rec = {**body, "hash": self._hash(body)}
        if self.key:
            rec["sig"] = hmac.new(self.key, rec["hash"].encode(), hashlib.sha256).hexdigest()
        self.records.append(rec)
        return rec

    def verify(self) -> bool:
        prev = "0" * 64
        for r in self.records:
            body = {k: r[k] for k in ("ts", "prev", "data")}
            if r["prev"] != prev or self._hash(body) != r["hash"]:
                return False
            if self.key and not hmac.compare_digest(
                    r.get("sig", ""), hmac.new(self.key, r["hash"].encode(), hashlib.sha256).hexdigest()):
                return False
            prev = r["hash"]
        return True


_DOMAIN_PLAIN = {"clear": "a well-understood change",
                 "complicated": "needs analysis; an expert should be able to explain it",
                 "complex": "uncertain outcome; change in small, tested steps"}


def explain(rec: dict, runbook: str | None = None) -> dict:
    """Deterministic plain-language explanation of a decision record (no model involved)."""
    pr, out, verdict = rec["predicted"], rec["outcome"], rec["verdict"]
    what = f"{rec['action']} on {rec['resource']}"
    cause, tickets = rec.get("cause", ""), rec.get("tickets") or []
    if out == "applied":
        real = rec.get("realized", {})
        summary = (f"Applied: {what}. Monthly cost changed {real.get('d_cost', 0):+.0f} "
                   f"(predicted {pr['d_cost']:+.0f}); CO2 {real.get('d_co2', 0):+.1f} kg.")
        nxt = "Watch performance for the next day and compare realized vs predicted; accurate results build trust."
    elif out == "rolled_back":
        if cause == "slo_regression":
            summary = f"Rolled back automatically: {what} made performance (SLO) worse. Nothing was left changed."
            nxt = "Check this resource's spare capacity before trying again, or propose a smaller step."
        elif cause == "security_regression":
            summary = f"Rolled back automatically: {what} introduced a new security finding."
            nxt = (f"Ticket {', '.join(tickets)} opened for {rec['owner']}. Fix the finding, then re-propose."
                   if tickets else "The owner should fix the finding, then re-propose.")
        else:
            summary = f"Rolled back automatically: {what} failed partway and the previous state was restored."
            nxt = "Check connector permissions and logs, then retry."
    elif out == "shadow":
        summary = f"Shadow mode: {what} was evaluated but not applied. It would have been '{rec.get('verdict_would', 'allowed')}'."
        nxt = "Compare with what actually happens, then reconcile the result to build trust."
    elif verdict == "blocked":
        summary = f"Blocked by policy: {what}. " + "; ".join(rec["reasons"]).rstrip(".") + "."
        nxt = "Adjust the proposal to fit the policy, or ask the policy owner for an exception."
    elif verdict == "needs_approval" and any("approval must come from" in x for x in rec["reasons"]):
        summary = (f"Approval not accepted: {what} must be approved by {', '.join(rec['escalate_to'])}, "
                   f"not {rec.get('approved_by')}.")
        nxt = "Ask the named expert to review the evidence and approve or reject."
    elif verdict == "needs_approval":
        who = (f"{', '.join(rec['escalate_to'])} (named expert for this change)" if rec.get("escalate_to")
               else f"{rec['owner']} (accountable owner)")
        summary = f"Waiting for approval: {what} needs a decision from {who}."
        nxt = "The owner reviews the evidence and approves or rejects. If unsure, ask a senior engineer."
    else:
        summary = f"Recommendation only: {what}. Applying is switched off in this mode."
        nxt = "Switch to Active (after Shadow) when you are ready for changes to be applied."
    out_d = {"summary": summary,
             "why": "; ".join(rec["reasons"]),
             "risk": f"Predicted performance risk {pr['slo_risk']:.0%}; this is {_DOMAIN_PLAIN.get(rec['domain'], rec['domain'])}.",
             "rollback": ("Automatic: the previous state is saved before the change and restored if checks fail."
                          if out in ("applied", "rolled_back") else "Nothing has been changed yet."),
             "next_step": nxt}
    if runbook:
        out_d["runbook"] = runbook
    return out_d


_WHEN_KEYS = {"action", "domain", "resource", "owner", "stateful", "region", "min_abs_cost"}


def validate_pack(pack: dict) -> None:
    """Reject malformed packs. Typos fail loudly: a rule that silently never matches is dangerous."""
    for k in ("name", "version", "rules"):
        if k not in pack:
            raise ValueError(f"pack missing '{k}'")
    seen = set()
    for rule in pack["rules"]:
        for k in ("id", "when", "effect", "message"):
            if k not in rule:
                raise ValueError(f"rule missing '{k}': {rule.get('id', rule)}")
        rid = rule["id"]
        if rid in seen:
            raise ValueError(f"duplicate rule id {rid}")
        seen.add(rid)
        if rule["effect"] not in ("block", "require_approval"):
            raise ValueError(f"rule {rid}: effect must be 'block' or 'require_approval'")
        if not rule["when"]:
            raise ValueError(f"rule {rid}: needs at least one condition (an empty rule matches everything)")
        bad = set(rule["when"]) - _WHEN_KEYS
        if bad:
            raise ValueError(f"rule {rid}: unknown condition(s) {sorted(bad)}; allowed: {sorted(_WHEN_KEYS)}")
        ap = rule.get("approvers")
        if ap is not None and (rule["effect"] != "require_approval" or not isinstance(ap, list)
                               or not all(isinstance(a, str) for a in ap)):
            raise ValueError(f"rule {rid}: 'approvers' is a list of names, only for require_approval")


def _as_list(v):
    return [v] if isinstance(v, str) else list(v)


def rule_matches(when: dict, p, r) -> bool:
    """All listed conditions must hold (AND). Text conditions accept one value or a list; globs allowed."""
    if "action" in when and not any(fnmatch(p.action, g) for g in _as_list(when["action"])):
        return False
    if "resource" in when and not any(fnmatch(r.id, g) for g in _as_list(when["resource"])):
        return False
    if "domain" in when and p.domain.value not in _as_list(when["domain"]):
        return False
    if "owner" in when and r.owner not in _as_list(when["owner"]):
        return False
    if "region" in when and (p.new_region or r.region) not in _as_list(when["region"]):
        return False
    if "stateful" in when and r.stateful != when["stateful"]:
        return False
    if "min_abs_cost" in when and abs(p.d_cost) < when["min_abs_cost"]:
        return False
    return True


class Engine:
    def __init__(self, policy, connector, registry, mode=Mode.LEARN, ticketer=None, signing_key=None, runbooks=None):
        self.policy, self.c, self.mode = policy, connector, mode
        self.registry = {r.id: r for r in registry}
        self.ledger = Ledger(signing_key)
        self.packs: list[dict] = []          # expert policy packs
        self.runbooks = runbooks or {}       # action -> URL shown in explanations
        self._reconciled: set[int] = set()
        self.changes = 0
        self.streak: dict[str, int] = {}     # action -> consecutive clean applies
        self.samples: dict[str, list[float]] = {}
        self.learn_flags = {"traffic": True, "payloads": False}   # per data type
        self.tickets: list[dict] = []
        self.ticketer = ticketer or self._default_ticketer

    # ---- expert policy packs ----------------------------------------------
    def load_pack(self, pack: dict) -> str:
        validate_pack(pack)
        self.packs.append(pack)
        return pack["name"]

    def load_pack_file(self, path) -> str:
        with open(path) as f:
            return self.load_pack(json.load(f))

    def _pack_hits(self, p, r):
        return [(f"{pk['name']}:{rule['id']}", rule) for pk in self.packs for rule in pk["rules"]
                if rule_matches(rule["when"], p, r)]

    def _approvers(self, p, r) -> list[str]:
        return sorted({a for _, rule in self._pack_hits(p, r) if rule["effect"] == "require_approval"
                       for a in rule.get("approvers", [])})

    # ---- learn switch -------------------------------------------------
    def observe(self, kind: str, value: float) -> bool:
        if self.mode == Mode.OFF or not self.learn_flags.get(kind, False):
            return False
        self.samples.setdefault(kind, []).append(value)
        return True

    def baseline(self, kind: str):
        s = sorted(self.samples.get(kind, []))
        if len(s) < 5:              # cold start: refuse to invent a baseline
            return None
        return {"mean": sum(s) / len(s), "p95": s[int(0.95 * (len(s) - 1))], "n": len(s)}

    # ---- earned autonomy ------------------------------------------------
    def earned(self, p: Proposal, r: Resource) -> bool:
        """Autonomy is earned from the ledger, never granted for COMPLEX, stateful or irreversible changes."""
        return (p.domain == Domain.COMPLICATED and p.reversible and not r.stateful
                and self.streak.get(p.action, 0) >= self.policy.promote_after)

    def _track(self, action: str, clean: bool):
        self.streak[action] = self.streak.get(action, 0) + 1 if clean else 0

    # ---- gatekeeper ---------------------------------------------------
    def decide(self, p: Proposal, r: Resource):
        pol = self.policy
        region = p.new_region or r.region
        if region not in pol.allowed_regions:
            return Verdict.BLOCKED, [f"region {region} not allowed"]
        if p.slo_risk > pol.max_slo_risk or r.slo_headroom - p.slo_risk < pol.min_headroom:
            return Verdict.BLOCKED, ["SLO risk exceeds policy"]
        co2_worst = p.co2_range[1] if p.co2_range else p.d_co2      # conservative bound
        if -p.d_cost - pol.carbon_price_per_kg * co2_worst <= 0:
            return Verdict.BLOCKED, ["no net benefit (cost + priced carbon)"]
        hits = self._pack_hits(p, r)
        for key, rule in hits:                                      # expert block rules always win
            if rule["effect"] == "block":
                return Verdict.BLOCKED, [f"[{key}] {rule['message']}"]
        if self.mode in (Mode.OFF, Mode.LEARN):
            return Verdict.RECOMMEND, [f"mode={self.mode.value}: recommend-only"]
        why = []
        if not p.reversible or r.stateful:
            why.append("irreversible or stateful")
        earned = self.earned(p, r)
        if p.domain != Domain.CLEAR and not earned:
            why.append(f"domain={p.domain.value}")
            if self.baseline("traffic") is None:
                why.append("cold start: no traffic baseline")
        for key, rule in hits:                                      # expert rules beat earned autonomy
            if rule["effect"] == "require_approval":
                why.append(f"[{key}] {rule['message']}")
        if self.changes >= pol.max_changes_per_window:
            why.append("change budget exhausted")
        if p.co2_range and p.d_co2 < 0 <= p.co2_range[1] and pol.carbon_price_per_kg > 0:
            why.append("carbon benefit uncertain (range crosses zero)")
        if why:
            v, reasons = Verdict.NEEDS_APPROVAL, why
        elif earned:
            v, reasons = Verdict.AUTO, [f"earned autonomy: {self.streak[p.action]} clean applies of '{p.action}'"]
        else:
            v, reasons = Verdict.AUTO, ["clear, reversible, within policy"]
        if self.mode == Mode.SHADOW:                 # evaluate fully, apply nothing
            return Verdict.SHADOW, [f"shadow: would be {v.value}"] + reasons
        return v, reasons

    # ---- execute with recovery -----------------------------------------
    def execute(self, p: Proposal, approved_by: str | None = None) -> dict:
        r = self.registry[p.resource_id]
        verdict, reasons = self.decide(p, r)
        rec = {"schema": SCHEMA_VERSION, "kind": "decision", "id": len(self.ledger.records),
               "resource": r.id, "owner": r.owner, "action": p.action,
               "domain": p.domain.value, "verdict": verdict.value, "reasons": reasons,
               "predicted": {"d_cost": p.d_cost, "d_co2": p.d_co2, "slo_risk": p.slo_risk,
                             **({"d_co2_range": list(p.co2_range)} if p.co2_range else {})},
               "approved_by": approved_by}
        need = self._approvers(p, r) if verdict == Verdict.NEEDS_APPROVAL else []
        if need:
            rec["escalate_to"] = need                               # named experts who may approve
        wrong = bool(approved_by and need and approved_by not in need)
        if wrong:
            reasons.append(f"approval must come from: {', '.join(need)}")
        go = verdict == Verdict.AUTO or (verdict == Verdict.NEEDS_APPROVAL and approved_by and not wrong)
        if not go:
            rec["outcome"] = "shadow" if verdict == Verdict.SHADOW else "not_applied"
            if verdict == Verdict.SHADOW:
                rec["verdict_would"] = reasons[0].replace("shadow: would be ", "")
            return self._emit(rec)

        snap = copy.deepcopy(r)
        before_findings = self.c.scan(r)
        cost0, co20 = r.monthly_cost, r.monthly_kg_co2
        try:
            self.c.apply(r, p)
            slo_ok = self.c.probe(r)
            new_findings = self.c.scan(r) - before_findings
        except Exception as e:                      # recover from partial failure
            self.c.restore(r, snap)
            self._track(p.action, False)
            rec.update(outcome="rolled_back", cause=f"apply_error: {e}")
            return self._emit(rec)

        if not slo_ok or new_findings:              # verify before calling it done
            self.c.restore(r, snap)
            self._track(p.action, False)
            rec.update(outcome="rolled_back",
                       cause="slo_regression" if not slo_ok else "security_regression",
                       tickets=[self.ticketer(f, r) for f in sorted(new_findings)])
        else:
            self.changes += 1
            real = r.monthly_cost - cost0
            err = abs(real - p.d_cost) / max(abs(p.d_cost), 1e-9)
            self._track(p.action, err <= self.policy.max_pred_error)   # inaccurate predictions reset trust
            rec.update(outcome="applied", pred_error=round(err, 3),
                       realized={"d_cost": real, "d_co2": r.monthly_kg_co2 - co20})
        return self._emit(rec)

    def _emit(self, rec: dict) -> dict:
        rec["explanation"] = explain(rec, self.runbooks.get(rec["action"]))
        return self.ledger.append(rec)

    def reconcile(self, decision_id: int, realized_d_cost: float, realized_d_co2: float | None = None) -> dict:
        """Compare a shadow decision's prediction with what was actually observed."""
        d = self.ledger.records[decision_id]["data"]
        if d.get("kind") != "decision" or d.get("outcome") != "shadow":
            raise ValueError("only shadow decisions can be reconciled")
        if decision_id in self._reconciled:
            raise ValueError("already reconciled")
        self._reconciled.add(decision_id)
        pred = d["predicted"]["d_cost"]
        err = abs(realized_d_cost - pred) / max(abs(pred), 1e-9)
        clean = err <= self.policy.max_pred_error
        self._track(d["action"], clean)               # accurate shadow predictions build trust
        return self.ledger.append({"schema": SCHEMA_VERSION, "kind": "reconciliation",
                                   "decision_id": decision_id, "resource": d["resource"],
                                   "action": d["action"], "predicted_d_cost": pred,
                                   "realized_d_cost": realized_d_cost, "realized_d_co2": realized_d_co2,
                                   "pred_error": round(err, 3), "clean": clean})

    def export_jsonl(self, path):
        with open(path, "w") as f:
            for r in self.ledger.records:
                f.write(json.dumps(r, default=str) + "\n")

    def _default_ticketer(self, finding, r):
        t = {"id": f"SEC-{len(self.tickets) + 1}", "finding": finding,
             "resource": r.id, "owner": r.owner, "severity": "high",
             "retest_on_close": True}
        self.tickets.append(t)
        return t["id"]


_REQUIRED = {"decision": ("id", "resource", "owner", "action", "domain", "verdict", "reasons", "predicted", "outcome"),
             "reconciliation": ("decision_id", "action", "predicted_d_cost", "realized_d_cost", "pred_error", "clean")}


def validate_record(d: dict) -> list[str]:
    """Minimal dependency-free check against schema/decision-record.schema.json."""
    errs = [] if d.get("schema") == SCHEMA_VERSION else ["bad or missing schema version"]
    req = _REQUIRED.get(d.get("kind"))
    if req is None:
        return errs + ["unknown kind"]
    return errs + [f"missing {k}" for k in req if k not in d]


class SimConnector:
    """In-memory stand-in for real infrastructure connectors."""

    def __init__(self, slo_breaking=(), insecure=(), failing=(), drift=1.0):
        self.drift = drift      # realized/predicted cost ratio (1.0 = accurate)
        self.slo_breaking, self.insecure, self.failing = set(slo_breaking), set(insecure), set(failing)
        self.state: dict[str, str] = {}

    def apply(self, r, p):
        if p.action in self.failing:
            raise RuntimeError("API timeout")
        r.monthly_cost += p.d_cost * self.drift
        r.monthly_kg_co2 += p.d_co2
        if p.new_region:
            r.region = p.new_region
        r.config.update(p.new_config)
        self.state[r.id] = p.action

    def probe(self, r):
        return self.state.get(r.id) not in self.slo_breaking

    def scan(self, r):
        return {"PUBLIC_ACCESS"} if self.state.get(r.id) in self.insecure else set()

    def restore(self, r, snap):
        r.__dict__.update(copy.deepcopy(snap.__dict__))
        self.state.pop(r.id, None)


# ---------------------------------------------------------------------------
def _selftest():
    def mk(mode=Mode.ACTIVE, price=0.0, **kw):
        res = [Resource("vol-1", "team-a", "eu-west", 40, 2, 0.6),
               Resource("db-1", "team-b", "eu-west", 900, 30, 0.4, stateful=True),
               Resource("web-1", "team-c", "eu-west", 500, 20, 0.5)]
        pol = Policy({"eu-west", "in-south"}, carbon_price_per_kg=price)
        return Engine(pol, SimConnector(**kw), res, mode=mode)

    def clear(rid="vol-1", action="delete_idle", dc=-40.0):
        return Proposal(rid, action, Domain.CLEAR, dc, -2, 0.0)

    def out(e, p, **k):
        return e.execute(p, **k)["data"]

    # 1 learn mode only recommends
    e = mk(Mode.LEARN); d = out(e, clear())
    assert d["verdict"] == "recommend" and d["outcome"] == "not_applied"
    assert e.registry["vol-1"].monthly_cost == 40
    # 2 active auto-apply, ledger intact
    e = mk(); d = out(e, clear())
    assert d["outcome"] == "applied" and e.registry["vol-1"].monthly_cost == 0
    assert e.ledger.verify()
    # 3 residency violation blocked
    d = out(mk(), Proposal("web-1", "move", Domain.COMPLICATED, -50, -10, 0.05, new_region="us-east"))
    assert d["verdict"] == "blocked"
    # 4 complicated change needs approval, then applies
    e = mk(); p = Proposal("web-1", "rightsize", Domain.COMPLICATED, -100, -5, 0.05)
    assert out(e, p)["outcome"] == "not_applied"
    assert out(e, p, approved_by="alice")["outcome"] == "applied"
    # 5 SLO regression -> automatic rollback
    e = mk(slo_breaking={"downsize"})
    d = out(e, Proposal("web-1", "downsize", Domain.COMPLICATED, -100, -5, 0.1), approved_by="alice")
    assert d["outcome"] == "rolled_back" and d["cause"] == "slo_regression"
    assert e.registry["web-1"].monthly_cost == 500
    # 6 security regression -> rollback + ticket for the owner
    e = mk(insecure={"open_bucket"}); d = out(e, clear(action="open_bucket"))
    assert d["cause"] == "security_regression" and len(e.tickets) == 1
    assert e.tickets[0]["owner"] == "team-a" and e.registry["vol-1"].monthly_cost == 40
    # 7 partial failure recovered
    e = mk(failing={"resize"}); d = out(e, clear(action="resize"))
    assert d["outcome"] == "rolled_back" and d["cause"].startswith("apply_error")
    # 8 change budget exhausted -> approval required
    e = mk()
    for i in range(3):
        assert out(e, clear(action=f"a{i}", dc=-1))["outcome"] == "applied"
    assert out(e, clear(action="a4", dc=-1))["verdict"] == "needs_approval"
    # 9 tamper detection
    e = mk(); out(e, clear()); e.ledger.records[0]["data"]["outcome"] = "forged"
    assert not e.ledger.verify()
    # 10 learn switch per data type + cold start
    e = mk(); assert not e.observe("payloads", 1.0)
    for v in (10, 12, 11, 13): e.observe("traffic", v)
    assert e.baseline("traffic") is None
    e.observe("traffic", 12); assert e.baseline("traffic")["n"] == 5
    assert not mk(Mode.OFF).observe("traffic", 1.0)
    # 11 stateful resource never auto-applies
    assert out(mk(), clear("db-1", "x", -10))["verdict"] == "needs_approval"
    # 12 carbon objective: costs more but cuts emissions
    p = Proposal("web-1", "greener_region", Domain.COMPLICATED, 5, -10, 0.05)
    assert out(mk(price=0.0), p)["verdict"] == "blocked"
    assert out(mk(price=1.0), p)["verdict"] == "needs_approval"
    # 13 earned autonomy: approvals build trust, inaccuracy or rollback resets it
    res = [Resource("web-1", "team-c", "eu-west", 500, 20, 0.5), Resource("db-1", "team-b", "eu-west", 900, 30, 0.4, stateful=True)]
    e = Engine(Policy({"eu-west"}, max_changes_per_window=20), SimConnector(), res, mode=Mode.ACTIVE)
    rs = lambda dom=Domain.COMPLICATED, rid="web-1": Proposal(rid, "rightsize", dom, -1, -0.1, 0.05)
    for _ in range(3):
        assert out(e, rs(), approved_by="alice")["outcome"] == "applied"
    d = out(e, rs())
    assert d["verdict"] == "auto" and d["reasons"][0].startswith("earned autonomy")
    assert out(e, rs(Domain.COMPLEX))["verdict"] == "needs_approval"          # never for COMPLEX
    assert out(e, rs(rid="db-1"))["verdict"] == "needs_approval"              # never for stateful
    e.c.drift = 0.1                                                           # predictions now wrong
    out(e, rs())
    assert out(e, rs())["verdict"] == "needs_approval"                        # trust lost
    # 14 shadow mode: evaluate without applying; reconciled accuracy earns autonomy
    web = lambda: [Resource("web-1", "team-c", "eu-west", 500, 20, 0.5)]
    e = Engine(Policy({"eu-west"}, max_changes_per_window=20), SimConnector(), web(), mode=Mode.SHADOW)
    sp = lambda: Proposal("web-1", "rightsize", Domain.COMPLICATED, -10, -1, 0.05)
    for _ in range(3):
        d = out(e, sp())
        assert d["verdict"] == "shadow" and d["outcome"] == "shadow" and d["reasons"][0].startswith("shadow: would be")
        assert e.registry["web-1"].monthly_cost == 500                       # nothing applied
        e.reconcile(d["id"], -9)
    try:
        e.reconcile(d["id"], -9); raise SystemExit("double reconcile allowed")
    except ValueError:
        pass
    e.mode = Mode.ACTIVE
    assert out(e, sp())["verdict"] == "auto"                                 # earned via shadow accuracy
    e.mode = Mode.SHADOW
    e.reconcile(out(e, sp())["id"], -2)                                      # inaccurate prediction
    e.mode = Mode.ACTIVE
    assert out(e, sp())["verdict"] == "needs_approval"
    # 15 carbon uncertainty: gate uses the conservative bound
    cp = lambda dc, rng, dom=Domain.COMPLICATED: Proposal("web-1", "greener", dom, dc, -10, 0.05, co2_range=rng)
    e = Engine(Policy({"eu-west"}, carbon_price_per_kg=1.0), SimConnector(), web(), mode=Mode.ACTIVE)
    assert out(e, cp(5, (-14, 2)))["verdict"] == "blocked"                   # worst case adds emissions
    assert out(e, cp(5, (-14, -8)))["verdict"] == "needs_approval"           # benefit holds across range
    d = out(e, cp(-20, (-14, 1), Domain.CLEAR))
    assert d["verdict"] == "needs_approval" and "carbon benefit uncertain (range crosses zero)" in d["reasons"]
    # 16 signed ledger
    e = Engine(Policy({"eu-west"}), SimConnector(), web(), mode=Mode.ACTIVE, signing_key=b"k")
    out(e, Proposal("web-1", "x", Domain.CLEAR, -1, -0.1, 0.0)); assert e.ledger.verify()
    e.ledger.records[0]["sig"] = "0" * 64; assert not e.ledger.verify()
    # 17 open record schema
    e = Engine(Policy({"eu-west"}), SimConnector(), web(), mode=Mode.SHADOW)
    d = out(e, Proposal("web-1", "x", Domain.CLEAR, -1, -0.1, 0.0)); rc = e.reconcile(d["id"], -1)["data"]
    assert validate_record(d) == [] and validate_record(rc) == [] and validate_record({"kind": "decision"})
    # 18 plain-language explanations on every decision, covered by the hash chain
    res = [Resource("web-1", "team-c", "eu-west", 500, 20, 0.5), Resource("db-1", "team-b", "eu-west", 900, 30, 0.4, stateful=True)]
    e = Engine(Policy({"eu-west"}), SimConnector(slo_breaking={"slow"}, insecure={"open"}, failing={"boom"}), res,
               mode=Mode.ACTIVE, runbooks={"rightsize": "https://wiki.example/runbooks/rightsize"})
    mk2 = lambda a, rid="web-1": Proposal(rid, a, Domain.COMPLICATED, -10, -1, 0.05)
    recs = {k: e.execute(mk2(k), approved_by="alice")["data"] for k in ("rightsize", "slow", "open", "boom")}
    assert recs["rightsize"]["explanation"]["summary"].startswith("Applied")
    assert recs["rightsize"]["explanation"]["runbook"].endswith("rightsize")
    assert "performance" in recs["slow"]["explanation"]["summary"]
    assert "SEC-1" in recs["open"]["explanation"]["next_step"]
    assert "failed partway" in recs["boom"]["explanation"]["summary"]
    assert "approval" in e.execute(mk2("rightsize", "db-1"))["data"]["explanation"]["summary"].lower()
    bad = e.execute(Proposal("web-1", "move", Domain.COMPLICATED, -10, -1, 0.05, new_region="us-east"))["data"]
    assert bad["explanation"]["summary"].startswith("Blocked by policy")
    assert e.ledger.verify()
    e.ledger.records[0]["data"]["explanation"]["summary"] = "edited"
    assert not e.ledger.verify()
    # 19 expert policy packs: blocks, named approvers, typo safety, beat earned autonomy
    pack = {"name": "ex", "version": "1", "rules": [
        {"id": "no-db-resize", "when": {"action": "resize*", "resource": "db-*"}, "effect": "block", "message": "Use the DBA process."},
        {"id": "delete-sre", "when": {"action": "delete_*"}, "effect": "require_approval", "approvers": ["sre-lead"], "message": "SRE signs off on deletions."},
        {"id": "pay-review", "when": {"owner": "payments", "domain": "complicated"}, "effect": "require_approval", "message": "Payments changes need review."}]}
    res = [Resource("vol-1", "team-a", "eu-west", 40, 2, 0.6), Resource("db-1", "team-b", "eu-west", 900, 30, 0.4),
           Resource("pay-1", "payments", "eu-west", 300, 10, 0.6)]
    e = Engine(Policy({"eu-west"}, max_changes_per_window=20), SimConnector(), res, mode=Mode.ACTIVE)
    e.load_pack(pack)
    d = e.execute(Proposal("db-1", "resize_up", Domain.CLEAR, -5, -0.1, 0.0))["data"]
    assert d["verdict"] == "blocked" and d["reasons"][0].startswith("[ex:no-db-resize]")
    dl = Proposal("vol-1", "delete_idle", Domain.CLEAR, -40, -2, 0.0)
    d = e.execute(dl)["data"]
    assert d["verdict"] == "needs_approval" and d["escalate_to"] == ["sre-lead"]
    d = e.execute(dl, approved_by="alice")["data"]                          # wrong approver
    assert d["outcome"] == "not_applied" and d["explanation"]["summary"].startswith("Approval not accepted")
    assert e.execute(dl, approved_by="sre-lead")["data"]["outcome"] == "applied"
    tune = Proposal("pay-1", "tune", Domain.COMPLICATED, -1, -0.1, 0.05)
    for _ in range(3):
        assert e.execute(tune, approved_by="bob")["data"]["outcome"] == "applied"
    assert e.streak["tune"] >= 3
    assert e.execute(tune)["data"]["verdict"] == "needs_approval"         # expert rule beats earned autonomy
    other = Proposal("vol-1", "tune", Domain.COMPLICATED, -1, -0.1, 0.05)
    assert e.execute(other)["data"]["verdict"] == "auto"                  # non-matching resource still earns autonomy
    base = {"name": "x", "version": "1"}
    for rule in ({"id": "r", "when": {"acton": "x"}, "effect": "block", "message": "m"},                 # typo
                 {"id": "r", "when": {}, "effect": "block", "message": "m"},                              # matches everything
                 {"id": "r", "when": {"action": "x"}, "effect": "allow", "message": "m"},
                 {"id": "r", "when": {"action": "x"}, "effect": "block", "message": "m", "approvers": ["a"]}):
        try:
            e.load_pack({**base, "rules": [rule]})
            raise AssertionError("bad pack accepted")
        except ValueError:
            pass
    assert all(not validate_record(x["data"]) for x in e.ledger.records) and e.ledger.verify()
    print("all 19 checks passed")


if __name__ == "__main__":
    _selftest()
