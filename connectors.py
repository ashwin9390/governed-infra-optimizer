"""
Connector interface plus a dry-run InventoryConnector for real inventory/billing exports.

To support a new platform, subclass Connector and implement five methods.
InventoryConnector reads a JSON or CSV export and applies changes IN MEMORY ONLY (dry run),
so teams can evaluate the engine on their own data with zero risk to production.
"""
from __future__ import annotations
import copy, csv, json
from abc import ABC, abstractmethod
from datetime import datetime, timedelta, timezone
from optimizer_core import Resource, Proposal, Domain, Engine, Policy, Mode


class Connector(ABC):
    @abstractmethod
    def list_resources(self) -> list[Resource]: ...
    @abstractmethod
    def apply(self, r: Resource, p: Proposal) -> None: ...      # raise on failure
    @abstractmethod
    def probe(self, r: Resource) -> bool: ...                   # True if SLOs still hold
    @abstractmethod
    def scan(self, r: Resource) -> set: ...                     # set of security finding ids
    @abstractmethod
    def restore(self, r: Resource, snap: Resource) -> None: ...  # undo apply


def _truthy(v) -> bool:
    return v if isinstance(v, bool) else str(v).strip().lower() in ("1", "true", "yes", "y")


class InventoryConnector(Connector):
    """Dry-run connector. Plug monitoring/security checks via probe_fn / scan_fn."""

    DRY_RUN = True

    def __init__(self, path: str, probe_fn=None, scan_fn=None):
        self.path, self.probe_fn, self.scan_fn = path, probe_fn, scan_fn

    def list_resources(self) -> list[Resource]:
        if self.path.endswith(".csv"):
            with open(self.path, newline="") as f:
                rows = list(csv.DictReader(f))
        else:
            with open(self.path) as f:
                rows = json.load(f)
        return [Resource(id=r["id"], owner=r["owner"], region=r["region"],
                         monthly_cost=float(r["monthly_cost"]), monthly_kg_co2=float(r["monthly_kg_co2"]),
                         slo_headroom=float(r.get("slo_headroom", 0.5)),
                         stateful=_truthy(r.get("stateful", False))) for r in rows]

    def apply(self, r, p):
        r.monthly_cost += p.d_cost
        r.monthly_kg_co2 += p.d_co2
        if p.new_region:
            r.region = p.new_region
        r.config.update(p.new_config)

    def probe(self, r):
        return self.probe_fn(r) if self.probe_fn else True

    def scan(self, r):
        return set(self.scan_fn(r)) if self.scan_fn else set()

    def restore(self, r, snap):
        r.__dict__.update(copy.deepcopy(snap.__dict__))


class AwsReadOnlyConnector(InventoryConnector):
    """Read-only AWS EC2 inventory and idle-instance proposals.

    Pass boto3 clients in (ec2, cloudwatch) with least-privilege read credentials.
    It never writes to AWS: apply() changes the in-memory copy only (DRY_RUN).
    Tested with fake clients, NOT against a live account. Prices and carbon figures
    are inputs you supply (monthly per instance type); unknown types are skipped.
    """

    def __init__(self, ec2, cloudwatch, prices, kg_co2=None, region="eu-west-1",
                 probe_fn=None, scan_fn=None):
        super().__init__("", probe_fn, scan_fn)
        self.ec2, self.cw, self.prices = ec2, cloudwatch, prices
        self.kg, self.region = kg_co2 or {}, region

    def list_resources(self):
        out = []
        resp = self.ec2.describe_instances(Filters=[{"Name": "instance-state-name", "Values": ["running"]}])
        for rsv in resp["Reservations"]:
            for i in rsv["Instances"]:
                price = self.prices.get(i["InstanceType"])
                if price is None:
                    continue                                    # never guess a price
                tags = {t["Key"]: t["Value"] for t in i.get("Tags", [])}
                out.append(Resource(i["InstanceId"], tags.get("owner", "unassigned"), self.region,
                                    price, self.kg.get(i["InstanceType"], 0.0),
                                    config={"type": i["InstanceType"]}))
        return out

    def avg_cpu(self, instance_id, days=14, now=None):
        now = now or datetime.now(timezone.utc)
        r = self.cw.get_metric_statistics(
            Namespace="AWS/EC2", MetricName="CPUUtilization",
            Dimensions=[{"Name": "InstanceId", "Value": instance_id}],
            StartTime=now - timedelta(days=days), EndTime=now, Period=86400, Statistics=["Average"])
        pts = r.get("Datapoints", [])
        return sum(p["Average"] for p in pts) / len(pts) if pts else None

    def propose_idle(self, resources, cpu_max=5.0, days=14, co2_uncertainty=0.5):
        """Stop-instance proposals for low-CPU instances. Unowned instances are skipped."""
        props = []
        for r in resources:
            if r.owner == "unassigned":
                continue                                        # every change needs an owner
            cpu = self.avg_cpu(r.id, days)
            if cpu is not None and cpu < cpu_max:
                u = co2_uncertainty
                props.append(Proposal(r.id, "stop_idle_instance", Domain.COMPLICATED,
                                      -r.monthly_cost, -r.monthly_kg_co2, 0.05,
                                      co2_range=(-r.monthly_kg_co2 * (1 + u), -r.monthly_kg_co2 * (1 - u))))
        return props


def _selftest():
    class FakeEC2:
        def __init__(self): self.calls = []
        def describe_instances(self, **kw):
            self.calls.append("describe_instances")
            mk = lambda i, t, tags: {"InstanceId": i, "InstanceType": t, "Tags": tags}
            own = lambda o: [{"Key": "owner", "Value": o}]
            return {"Reservations": [{"Instances": [mk("i-1", "m5.large", own("team-a")),
                    mk("i-2", "m5.large", own("team-b")), mk("i-3", "m5.large", []),
                    mk("i-4", "weird.type", own("team-a"))]}]}

    class FakeCW:
        cpu = {"i-1": 1.0, "i-2": 40.0, "i-3": 0.5}
        def get_metric_statistics(self, **kw):
            v = self.cpu.get(kw["Dimensions"][0]["Value"])
            return {"Datapoints": [] if v is None else [{"Average": v}] * 3}

    ec2 = FakeEC2()
    c = AwsReadOnlyConnector(ec2, FakeCW(), {"m5.large": 70.0}, {"m5.large": 9.0})
    res = c.list_resources()
    assert [r.id for r in res] == ["i-1", "i-2", "i-3"]                  # unknown price skipped
    props = c.propose_idle(res)
    assert [p.resource_id for p in props] == ["i-1"]                      # busy and unowned skipped
    assert props[0].co2_range == (-13.5, -4.5)
    e = Engine(Policy({"eu-west-1"}, carbon_price_per_kg=1.0), c, res, mode=Mode.ACTIVE)
    d = e.execute(props[0])["data"]
    assert d["verdict"] == "needs_approval" and d["outcome"] == "not_applied"
    d = e.execute(props[0], approved_by="alice")["data"]
    assert d["outcome"] == "applied" and e.registry["i-1"].monthly_cost == 0
    assert ec2.calls and set(ec2.calls) == {"describe_instances"}         # read-only: no write calls
    assert e.ledger.verify()
    print("connector checks passed")


if __name__ == "__main__":
    _selftest()
