# Extending the optimizer: a simple flow

```
  your inventory/billing  ->  Connector  ->  Engine (policy gate)
                                              |
        OFF / LEARN  ->  SHADOW  ->  ACTIVE   |   verify SLO + security -> commit or roll back
        (observe)       (evaluate,            v
                         no apply)      Signed decision ledger (dr/0.1)
                           |                  |
                  reconcile with observed     +--> dashboard, tickets, audit export
                  numbers -> earns autonomy
```

## Roll it out in six steps
1. **Describe your estate.** Export an inventory (JSON or CSV) with `id, owner, region, monthly_cost, monthly_kg_co2, slo_headroom, stateful`. Every resource needs an owner.
2. **Write a policy** (`examples/policy.json`): allowed regions, SLO limits, change budget, carbon price, how many clean results earn autonomy.
3. **Start in dry run.** `InventoryConnector` applies changes in memory only. Run `python examples/run_flow.py`.
4. **Run SHADOW mode** on real proposals. Nothing is applied. Reconcile each decision with what you later observe (`engine.reconcile(id, observed_cost)`).
5. **Switch to ACTIVE** for clear, reversible changes first. Actions with a clean, accurate track record earn auto-apply; COMPLEX, stateful and irreversible changes never do.
6. **Export the ledger** (`engine.export_jsonl`) for auditors or other tools. Records follow `schema/decision-record.schema.json`.

## Extension points
| Want to... | Do this |
|---|---|
| Read a live AWS account (read-only) | `AwsReadOnlyConnector(ec2, cloudwatch, prices)` with your own boto3 clients; it proposes idle-instance stops and never writes to AWS |
| Link runbooks | Pass `runbooks={action: url}` to `Engine`; each decision's plain-language explanation then links to it |
| Encode expert rules | Write a policy pack (see `examples/packs/payments-safety.json`) and load it with `engine.load_pack_file(path)`. Rules can `block` or `require_approval` and name the experts who may approve |
| Support a new platform | Subclass `Connector` in `connectors.py` (5 methods) |
| Add real SLO checks | Pass `probe_fn(resource) -> bool` to `InventoryConnector`, or implement `probe` |
| Add security scans | Pass `scan_fn(resource) -> set of finding ids`; new findings roll the change back |
| Send tickets to Jira/ServiceNow | Pass `ticketer=fn(finding, resource) -> ticket_id` to `Engine` |
| Change autonomy rules | Edit the policy file (`promote_after`, `max_pred_error`) |
| Put a price on carbon | `carbon_price_per_kg` in the policy; give uncertain estimates as `co2_range` |
| Sign records | Pass `signing_key` to `Engine`; keep the key in your secret store |
| Consume records elsewhere | Validate against the JSON Schema; `validate_record` is a minimal built-in check |

## Before production
Replace the dry-run connector with one that has least-privilege, short-lived credentials; add a rollback test for each action type; keep the signing key out of source control; and treat the first weeks as shadow-only.

## Expert policy packs
A pack is a JSON file a senior engineer writes once; everyone's changes are checked against it.
- **Conditions** (all must hold): `action`, `resource` (globs like `db-*`), `domain`, `owner`, `region`, `stateful`, `min_abs_cost`.
- **Effects:** `block` (always wins) or `require_approval`, optionally with `approvers` (only those named people can approve).
- Expert rules beat earned autonomy: an action with a clean record still waits for the named expert if a rule says so.
- Typos fail loudly: unknown conditions, empty rules and bad effects are rejected when the pack loads.
- Try it: `python examples/run_packs.py`
