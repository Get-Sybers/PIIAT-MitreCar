# Static SQL snapshots (`sql/`)

Frozen, static `.sql` snapshots of the pipeline's two SQLite databases, kept for
safekeeping. They capture the **database structure** (and the superset reference
model seed) exactly as the project's own code produces it at the pinned
submodule commits — not hand-written SQL.

| File | What it holds |
|------|---------------|
| `car.sql` | **Schema only** — the 13 CAR-object tables (`authentication`, `driver`, `email`, `file`, `flow`, `http`, `module`, `process`, `registry`, `service`, `socket`, `thread`, `user_session`), each with its canonical property columns plus a `guid` and `timestamp` index. No event rows: CAR events only exist after evidence ingestion, and no evidence was ingested for this snapshot. |
| `superset.sql` | Schema (`model_object`, `relationship_type`, `relationship` + indexes) **plus the reference model seed**: `model_object` (38 rows) and `relationship_type` (243 rows), reconstructed from the pinned CAR + ATT&CK data-sources model. The `relationship` instance table is empty (those rows are cascaded from evidence, none ingested here). |

## Deliberate exception to the "nothing generated is committed" convention

This repository normally commits **nothing generated**: `car.db` is gitignored,
the CAR/superset models are reconstructed live from the pinned submodules
(`build_data_model`), and `pyproject.toml` ships only the owned data files. These
`.sql` files are a **deliberate, one-off exception** — a frozen snapshot of the
DB structure (and superset reference seed) committed on purpose for safekeeping
and easy inspection, so the shape of the databases is reviewable without
building the submodules or running the pipeline. They are a point-in-time record,
not a live artifact; the live source of truth remains the pinned submodules and
the store code.

## Provenance

Generated from `piiat_mitrecar` (`store.py` / `superset.py`) at:

- PIIAT-MitreCar commit `92798f2cb554706172c43cb486a97ce2f1156af2`
- `third_party/car` submodule `1b922fe1527d956e222a99473472e594f10f610b`
- `third_party/attack-datasources` submodule `5d50f731de441eb09078623a2c29cc3420a01949`
- Date: 2026-09-01

Each `.sql` file carries the same provenance in its header comment.

## How to regenerate

The snapshots are produced by invoking the **same store classes the pipeline
uses**, then dumping with `sqlite3`'s `iterdump()` — no schema is re-implemented.

1. Check out the pinned submodules and install the package:

   ```sh
   git submodule update --init --recursive third_party/car third_party/attack-datasources
   pip install -e .
   ```

2. Build each database and dump it to SQL:

   ```python
   import sqlite3
   from contextlib import closing
   from piiat_mitrecar import store, superset

   # car.sql — schema only (no evidence => no event rows)
   store.CarStore("car.db").close()
   with open("sql/car.sql", "w") as fh, closing(sqlite3.connect("car.db")) as con:
       fh.write("\n".join(con.iterdump()))

   # superset.sql — schema + reference model seed (relationship table stays empty)
   s = superset.SupersetStore("superset.db"); s.seed_model(); s.close()
   with open("sql/superset.sql", "w") as fh, closing(sqlite3.connect("superset.db")) as con:
       fh.write("\n".join(con.iterdump()))
   ```

   (Then re-add the provenance header comment block at the top of each file.)

Row counts will match the pinned model: `model_object` 38, `relationship_type`
243, `relationship` 0. If the submodule pins change, the seed changes with them.
