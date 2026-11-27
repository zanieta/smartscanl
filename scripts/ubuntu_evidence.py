"""Run from the installed application directory, using its Python environment."""
import argparse
import json

from scanner.ubuntu_evidence import collect


def main():
    parser = argparse.ArgumentParser(description="Collect read-only evidence on the current Ubuntu host.")
    parser.add_argument("--record-for-client", type=int, metavar="CLIENT_ID",
                        help="Explicitly store the observation for this existing organization.")
    client = parser.parse_args().record_for_client
    if client is not None and client < 1:
        parser.error("Use a positive client ID.")
    try:
        report = collect()
    except (OSError, ValueError):
        parser.exit(1, "Cannot read a supported Ubuntu operating-system identity. No report saved.\n")
    if client is None:
        print(json.dumps(report, indent=2))
        return
    from db.session import SessionLocal
    from db.store import get_client, persist_scan
    with SessionLocal() as db:
        if get_client(db, client) is None:
            parser.error("Client does not exist; report not saved.")
        persist_scan(db, report, "ubuntu", client_id=client)
    print(report["scan_id"])


if __name__ == "__main__":
    main()
