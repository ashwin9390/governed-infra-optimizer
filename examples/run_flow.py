"""
Simple end-to-end flow a team can copy:
  inventory -> policy -> SHADOW pass -> reconcile with observed numbers -> ACTIVE pass -> signed ledger
Run from the repo root:  python examples/run_flow.py
"""
import json, pathlib, sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from optimizer_core import Domain, Engine, Mode, Policy, Proposal
from connectors import InventoryConnector

here = pathlib.Path(__file__).parent
conn = InventoryConnector(str(here / "inventory.json"))                   # 1. connect (dry run)
policy = Policy.from_dict(json.loads((here / "policy.json").read_text()))  # 2. policy
engine = Engine(policy, conn, conn.list_resources(), mode=Mode.SHADOW, signing_key=b"change-me")
raw = json.loads((here / "proposals.json").read_text())


def build(x):
    x = dict(x)
    x.pop("observed_d_cost", None); x.pop("approved_by", None)
    if "co2_range" in x:
        x["co2_range"] = tuple(x["co2_range"])
    return Proposal(domain=Domain(x.pop("domain")), **x)


print("== 3. shadow pass (nothing is applied)")
for x in raw:
    d = engine.execute(build(x))["data"]
    print(f"  {d['action']:<22} {d['reasons'][0]}")
    engine.reconcile(d["id"], x["observed_d_cost"])                        # 4. compare with what you observed

engine.mode = Mode.ACTIVE
print("== 5. active pass")
for x in raw:
    d = engine.execute(build(x), approved_by=x.get("approved_by"))["data"]
    print(f"  {d['action']:<22} {d['verdict']:<15} -> {d['outcome']}")

out = here / "out"; out.mkdir(exist_ok=True)
engine.export_jsonl(str(out / "ledger.jsonl"))                             # 6. portable signed records
print("ledger verified:", engine.ledger.verify(), "| written to examples/out/ledger.jsonl")
