"""Runs a simulated scenario, writes ledger.json and a self-contained dashboard.html."""
import json, pathlib
from optimizer_core import *

def run():
    res = [Resource("vol-old-7", "platform", "eu-west", 40, 2, 0.6),
           Resource("web-api", "payments", "eu-west", 500, 20, 0.5),
           Resource("batch-etl", "data", "eu-west", 300, 25, 0.7),
           Resource("db-main", "payments", "eu-west", 900, 30, 0.4, stateful=True),
           Resource("cache-1", "platform", "eu-west", 120, 6, 0.6)]
    pol = Policy({"eu-west", "in-south"}, carbon_price_per_kg=2.0, max_changes_per_window=10,
                 blast_approval_at=8, blast_block_at=15)
    c = SimConnector(slo_breaking={"downsize_aggressive"}, insecure={"open_public_endpoint"})
    e = Engine(pol, c, res, mode=Mode.SHADOW, signing_key=b"demo-key-change-me",
               topology=Topology.from_file(pathlib.Path(__file__).parent / "examples" / "topology.json"))
    for v in (110, 125, 118, 140, 132, 127):
        e.observe("traffic", v)
    e.observe("payloads", 1)                      # ignored: payload learning is off
    # shadow phase: evaluate without applying, then reconcile with what was observed
    for rid, observed in (("cache-1", -7.5), ("batch-etl", -2.0)):
        sp = Proposal(rid, "scale_in_off_peak", Domain.COMPLICATED, -8, -0.8, 0.05, co2_range=(-1.2, -0.5))
        e.reconcile(e.execute(sp)["data"]["id"], observed)
    e.mode = Mode.ACTIVE
    D = Domain
    steps = [
        (Proposal("vol-old-7", "delete_idle_volume", D.CLEAR, -40, -2, 0.0), None),
        (Proposal("web-api", "rightsize_instances", D.COMPLICATED, -120, -4, 0.05), "alice"),
        (Proposal("web-api", "downsize_aggressive", D.COMPLICATED, -200, -8, 0.1), "alice"),
        (Proposal("cache-1", "open_public_endpoint", D.CLEAR, -10, -1, 0.0), None),
        (Proposal("batch-etl", "move_to_us_region", D.COMPLICATED, -60, -12, 0.05, new_region="us-east"), None),
        (Proposal("batch-etl", "shift_to_green_window", D.COMPLICATED, 3, -9, 0.05), "bob"),
        (Proposal("cache-1", "rightsize_instances", D.COMPLICATED, -5, -0.5, 0.05), "alice"),
        (Proposal("cache-1", "rightsize_instances", D.COMPLICATED, -5, -0.5, 0.05), "alice"),
        (Proposal("batch-etl", "rightsize_instances", D.COMPLICATED, -5, -0.5, 0.05), None),   # autonomy earned
        (Proposal("db-main", "consolidate_replicas", D.CLEAR, -150, -6, 0.1), None),
    ]
    for p, who in steps:
        e.execute(p, approved_by=who)
    data = {"records": e.ledger.records, "chain_ok": e.ledger.verify(), "tickets": e.tickets,
            "mode": e.mode.value, "flags": e.learn_flags, "baseline": e.baseline("traffic")}
    here = pathlib.Path(__file__).parent
    (here / "ledger.json").write_text(json.dumps(data, indent=2, default=str))
    html = (here / "dashboard_template.html").read_text().replace("__DATA__", json.dumps(data, default=str))
    (here / "dashboard.html").write_text(html)
    print("wrote ledger.json and dashboard.html; chain intact:", data["chain_ok"])

if __name__ == "__main__":
    run()
