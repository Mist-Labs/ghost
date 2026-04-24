# Ghost Persistence Architecture

Ghost uses a standard Diesel workflow for the live runtime:

- `migrations/` contains the ordered schema changes
- `diesel.toml` points Diesel CLI at `migrations/` and `src/schema.rs`
- `src/schema.rs` is the canonical Diesel table map
- `src/model.rs` holds the shared persistence models used by the runtime
- `src/db.rs` owns connection setup, migration execution, and all database queries

## Responsibilities

`src/model.rs`
- Shared row and input structs for incidents, proactive reports, scan runs, findings, disclosures, and monitor snapshots.

`src/db.rs`
- Creates the async Diesel pool.
- Applies pending migrations at startup.
- Exposes the full query surface used by the active runtime.

`migrations/*/up.sql`
- Forward schema changes.

`migrations/*/down.sql`
- Reverse schema changes for local rollback and iteration.

## Standard Workflow

0. Install the Diesel CLI if you do local schema work.
```bash
cargo install diesel_cli --no-default-features --features postgres
```

1. Create a new migration.
```bash
diesel migration generate add_new_table
```

2. Edit `up.sql` and `down.sql`.

3. Apply the migration locally.
```bash
diesel migration run
```

4. Refresh `src/schema.rs`.
```bash
diesel print-schema > src/schema.rs
```

5. Add or update shared structs in `src/model.rs`.

6. Add or update the query functions in `src/db.rs`.

7. Verify the runtime.
```bash
cargo check
cargo test
```

## Runtime Migration Behavior

Ghost applies pending migrations during startup before the async pool is created. That keeps local development and service startup aligned with the checked-in Diesel migration history instead of ad hoc schema bootstrapping.

## Guardrails

- Do not add new `CREATE TABLE IF NOT EXISTS` bootstrap blocks in runtime code.
- Do not scatter query helpers across feature modules.
- Keep `src/db.rs` as the single place for database access in the active service path.
- Keep `src/model.rs` focused on shared persistence shapes, not orchestration logic.
