"""Add the 2FA columns to an existing `users` table.

`Base.metadata.create_all()` creates missing *tables*; it never alters existing
ones. Any database created before 2FA landed therefore has a `users` table with
no `totp_secret`, and the app will raise UndefinedColumn on the first login.

Idempotent: run it as many times as you like, on Postgres or SQLite.

    python -m scripts.add_2fa_columns
"""
import sys

from sqlalchemy import inspect, text

from db.session import engine

# Chosen to be valid DDL on both Postgres and SQLite. SQLite has no native
# BOOLEAN, but accepts the keyword and stores 0/1 — which is what SQLAlchemy
# reads back as a bool anyway.
NEW_COLUMNS = {
    "totp_secret": "VARCHAR",
    "totp_last_counter": "INTEGER",
    "totp_failures": "INTEGER DEFAULT 0",
    "is_2fa_exempt": "BOOLEAN DEFAULT FALSE",
}


def main() -> int:
    inspector = inspect(engine)
    if "users" not in inspector.get_table_names():
        print("[2fa] No `users` table yet — nothing to migrate. "
              "init_db() will create it with the columns already present.")
        return 0

    existing = {c["name"] for c in inspector.get_columns("users")}
    missing = {name: ddl for name, ddl in NEW_COLUMNS.items() if name not in existing}

    if not missing:
        print("[2fa] All 2FA columns already present. Nothing to do.")
        return 0

    with engine.begin() as conn:
        for name, ddl in missing.items():
            conn.execute(text(f"ALTER TABLE users ADD COLUMN {name} {ddl}"))
            print(f"[2fa] users.{name} added ({ddl})")

        # Existing rows get NULL for a column added without a default. Backfill the
        # two that the app reads as counters/flags so no code path sees NULL where
        # it expects 0 or False.
        conn.execute(text("UPDATE users SET totp_failures = 0 WHERE totp_failures IS NULL"))
        conn.execute(text("UPDATE users SET is_2fa_exempt = FALSE WHERE is_2fa_exempt IS NULL"))

    print(f"[2fa] Done. Added {len(missing)} column(s). "
          f"Every existing account now has totp_secret = NULL and will be required "
          f"to enroll on its next login.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
