"""Blast radius: how far could a change reach?  Run: python examples/run_blast_radius.py"""
import pathlib, sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from optimizer_core import Domain, Engine, Mode, Policy, Proposal, Resource, SimConnector, Topology

here = pathlib.Path(__file__).parent
topo = Topology.from_file(here / "topology.json")
res = [Resource("vol-old-7", "platform", "eu-west", 40, 2, 0.6),
       Resource("cache-1", "platform", "eu-west", 120, 6, 0.6),
       Resource("db-main", "payments", "eu-west", 900, 30, 0.6),
       Resource("mystery-svc", "unknown", "eu-west", 80, 3, 0.6)]      # not in the map
e = Engine(Policy({"eu-west"}, blast_approval_at=4, blast_block_at=15), SimConnector(), res,
           mode=Mode.ACTIVE, topology=topo)
e.load_pack({"name": "checkout-guard", "version": "1", "rules": [
    {"id": "checkout-lead", "when": {"touches": "checkout-*"}, "effect": "require_approval",
     "approvers": ["checkout-lead"], "message": "Anything that can reach checkout needs the checkout lead."}]})

for rid in ("vol-old-7", "cache-1", "db-main", "mystery-svc"):
    d = e.execute(Proposal(rid, "tidy_up", Domain.CLEAR, -10, -1, 0.0))["data"]
    b = d["blast_radius"]
    print(f"{rid:<12} score={b['score']:<3} coverage={b['coverage']:<9} -> {d['verdict']}")
    print(f"             {d['explanation']['blast_radius']}")
