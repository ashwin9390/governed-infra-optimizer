# Governed Infra Optimizer

A prototype of an infrastructure optimizer that treats **every change as a governed, recoverable, auditable decision**, weighing cost, carbon, performance and security together.

> Status: working prototype. Connectors are simulated. See "What it does not cover".

## Why this project exists

Autonomous optimization is arriving, and several mature vendors already do safe, SLO-guarded auto-apply well. But the mechanics are mostly closed SaaS. This project is a small, **open reference implementation** of a governed-change pattern: apply optimizations safely and prove the result, in code you can read, self-host and extend.

It is not a competitor to those products. It is a transparent starting point and a research playground.

- **Why (Sinek):** make infrastructure optimization predictable, safe and transparent for finance, engineering and security alike.
- **How:** a policy gatekeeper, verify-then-commit recovery, and a tamper-evident ledger.
- **What:** a core engine plus a dashboard that opens with money and risk, then drills into policies and actions.

## Architecture

```text
 Connectors (read)        Learn switch            Gatekeeper (FD-ALM style)
 billing, metrics,  --->  OFF / LEARN / ACTIVE -> Cynefin class -> autonomy
 traffic, configs         per data type           region/residency, SLO headroom,
                          baselines + cold-start  change budget, blast radius, stateful/irreversible,
                                                  carbon-priced net benefit
                                                        |
                                                        v
 Recovery manager: snapshot -> apply -> probe SLO -> security scan
        | ok: commit                | fail: restore snapshot + open ticket for owner
        v                           v
 Decision Ledger (hash-chained): predicted vs realized cost, CO2, SLO, security,
 approver, outcome  ---> Dashboard (Why -> How -> What)
```

Modes: **Off** (no learning), **Learn** (collect baselines), **Shadow** (evaluate fully, apply nothing, reconcile with observed results), **Active** (apply within policy).

Key ideas:

0. **Earned autonomy:** autonomy is not configured once and forgotten. A repeated action class is promoted to auto-apply only after N clean, accurately predicted applies, and loses that trust on any rollback or inaccurate prediction. It is never granted to COMPLEX, stateful or irreversible changes.
1. **One Decision Record per change** ties all signals together.
2. **Verify before "done":** a change counts only if SLO and security checks pass; otherwise it rolls back automatically.
3. **Autonomy by risk (Cynefin):** clear and reversible changes may auto-apply; others need a named human approver.
4. **Carbon as an objective:** a carbon price can make a slightly costlier but greener change worthwhile, within residency and SLO limits.
5. **Open record + signing:** every decision is a `dr/0.1` JSON record (see `schema/decision-record.schema.json`) in a hash-chained ledger, optionally HMAC-signed.
6. **Plain-language explanations:** every decision record says what happened, why, the risk, how it rolls back and the next step (deterministic templates, no model), so less-experienced engineers can act safely and seniors review exceptions.
7. **Carbon ranges:** uncertain carbon estimates are passed as ranges and the gate uses the conservative bound.
8. **Expert policy packs:** a senior engineer's rules (block, or require approval from named experts) as shareable JSON, enforced for everyone and stronger than earned autonomy.
9. **Learn switch:** learning is opt-in per data type (payloads off by default) and refuses to invent baselines during cold start.
10. **Blast radius:** a dependency map shows how far a change could reach (dependents, customer-facing services, critical services). Larger radius means a human approver, then a block; an unmapped or stale resource is treated as risky, never as zero. Expert packs can match on `touches` and `min_blast_radius`.

## How it relates to existing tools

Mature products already cover many pieces (verify current features before comparing): autonomous optimizers with SLO guardrails and audit logs (e.g. Sedai, CAST AI), cost governance as code (e.g. Stacklet), unified cost and carbon platforms (e.g. Cirrus Nexus, TrueCarbon, cloud-provider carbon tools), and hash-chained audit logs in other domains.

What this project explores, to my knowledge and after a limited search:

- cost, carbon, SLO, security and approval in **one open decision record**
- a **security-regression gate** on cost changes, with owner ticket and retest hook
- **earned autonomy** driven by predicted-vs-realized accuracy in the ledger
- a small, readable, dependency-free codebase

I could not find an open tool combining all of these, but that is not proof none exists.

## Who can use it

FinOps and platform teams, SREs, security teams (ticket and retest flow), finance/sustainability leads, and open-source contributors who want a base for governed automation.

## How it is useful

Safer optimization, an audit trail for finance and compliance, fewer manual handoffs, and measurable predicted-vs-realized accuracy.

## What it does NOT cover

- Write-path cloud connectors and Kubernetes. Included: a connector interface, a dry-run `InventoryConnector` (JSON/CSV), and a read-only `AwsReadOnlyConnector` (EC2 + CloudWatch, boto3 clients injected) tested only with fake clients, never against a live account. Nothing here changes real infrastructure.
- Automatic dependency discovery: the dependency map is a JSON file you supply, and an incomplete map is the main limit of blast-radius checks
- Real attack simulation (only a security-regression gate with ticketing hook)
- Finance depth: ERP, payroll, commitments, multi-currency
- Carbon data feeds and accounting standards: carbon price and ranges are inputs you supply, not computed
- Authentication, multi-tenancy, secrets management, production hardening
- Statistical forecasting, ML learning beyond simple baselines
- Dashboard is static; it renders `ledger.json` and has no live data

## Future work

Automatic topology discovery (Terraform state, Kubernetes, OpenTelemetry traces) and canary sizing from blast radius, real connectors (AWS/Azure/GCP, Kubernetes, FOCUS billing), Jira/ServiceNow tickets with auto-retest, Terraform/Helm pull-request apply mode, traffic replay simulation, carbon-aware scheduling with live grid data, regional policy packs, signed portable evidence records, role-based views, and a threat model and evaluation harness for the optimizer itself.

## Quick start

```bash
python optimizer_core.py        # run the 21 self-checks
python connectors.py            # read-only AWS connector checks (fake clients)
python examples/run_blast_radius.py  # blast radius from a dependency map
python examples/run_packs.py    # expert policy packs and named approvers
python demo.py                  # simulate changes, write ledger.json + dashboard.html
python examples/run_flow.py     # inventory -> shadow -> reconcile -> active flow
```

To adapt it to your company, follow `docs/EXTEND.md`.
Open `dashboard.html` in a browser. Python 3.10+, no dependencies.

## 👤 Author & License

- **Author:** Ashwin — [@ashwin9390](https://github.com/ashwin9390)
- **License:** [MIT](LICENSE). See the [LICENSE file](LICENSE).
- **GitHub:** [ashwin9390/governed-infra-optimizer](https://github.com/ashwin9390/governed-infra-optimizer)
