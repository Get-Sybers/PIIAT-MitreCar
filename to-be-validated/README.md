# to-be-validated

CAR mapping **inferences that are not yet sample-verified**. They are kept here
as YAML specs — out of the active `piiat_mitrecar/mappings/` package, so the live
pipeline never runs an unvalidated mapping — but preserved so the technical work
is not lost.

Each entry is a complete, implementable spec (event → CAR object/action, the
action-decision logic, field mappings, join keys, and the reason it's unvalidated).

**To promote one:** confirm it against a real capture that actually contains the
event (e.g. an image with the relevant `auditpol` subcategory enabled), then port
the family into an active `mappings/*.py` map using this spec, and delete it here.

## Contents

- `evtx_audit.yml` — Windows Security-audit families (object-access 4663/4660/4670,
  registry-audit 4657, process-exit 4689, file-share 5140/5145, Windows Filtering
  Platform 5156/5157/5158, crypto key-file 5058). Schema-grounded from the
  documented Windows EventData schema; action decisions key on stable numeric
  AccessMask. Absent from all current corpora (except 5058, whose action is still
  an inference). The prior working Python implementation is in git history
  (`mappings/evtx_audit.py`, removed when this was quarantined).
- `spindle_identity.yml` — the spindle row identity (the minted guid every
  l2t/Plaso row carries): the cross-tool renderings not yet confirmed against a
  multi-tool corpus (`file_reference`, timestamps, browser `db_path`,
  `prefetch_hash`) and the one intended component the Plaso record shape cannot
  supply (the registry `value_name` — Plaso's registry rows are key-level).
