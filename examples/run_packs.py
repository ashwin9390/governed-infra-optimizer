"""Expert policy packs: a senior engineer's rules, enforced for everyone.  Run: python examples/run_packs.py"""
import pathlib, sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from optimizer_core import Domain, Engine, Mode, Policy, Proposal, Resource, SimConnector

here = pathlib.Path(__file__).parent
res = [Resource("vol-9", "platform", "eu-west", 40, 2, 0.6), Resource("db-main", "payments", "eu-west", 900, 30, 0.4)]
e = Engine(Policy({"eu-west"}), SimConnector(), res, mode=Mode.ACTIVE)
e.load_pack_file(here / "packs" / "payments-safety.json")

def show(label, p, who=None):
    d = e.execute(p, approved_by=who)["data"]
    print(f"{label:<34} {d['outcome']:<12} {d['explanation']['summary']}")

show("db resize (blocked by expert rule)", Proposal("db-main", "resize_down", Domain.CLEAR, -50, -2, 0.05))
delete = Proposal("vol-9", "delete_idle_volume", Domain.CLEAR, -40, -2, 0.0)
show("delete, no approver", delete)
show("delete, approved by wrong person", delete, "alice")
show("delete, approved by named expert", delete, "sre-lead")
