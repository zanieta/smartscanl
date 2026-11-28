# Ubuntu installer acceptance — 2026.11.28-dev.2

The tested installer is commit `17c4d3d9d3970d2662523894d7f44a7e3caff072`. This is a development candidate, not a production release tag. The first candidate failed unattended installation because Ollama required HOME. The second candidate sets a default in the installer and never invokes the application-owned virtualenv as root to produce the updater's database dump.

## What passed

- Fresh installation from the exact Git archive in a pristine Ubuntu 24.04.5 amd64 KVM guest without HOME.
- Upgrade from the unmodified `v2026.10.20-rc9` installer in another pristine guest, using an ordinary root environment for RC9. The update preserved the environment file, Nginx TLS configuration and an existing customer. The backup restored into a separate database with the customer intact.
- PostgreSQL, Nginx, the application, its CVE timer, login page and an unprivileged local Ubuntu observation passed after both paths. On upgrade the TLS check trusted a private test CA/certificate; the login checks exercised the second-factor challenge and authenticated emergency account. No live customer was accessed.
- 42 Ubuntu regression tests, eight Linux packaging checks and the separate PostgreSQL recovery rehearsal passed. The collector reports OS/kernel metadata and pending standard Ubuntu security package versions; it does not install packages.

Both guests used a real Ollama installation with the small `smollm2:135m` test model. Full NVD synchronization, production `gpt-oss:latest` capacity, public certificate issuance, other architectures, Windows and a remote customer deployment were not tested.

## Reproduce

From a clone of the Linux repository containing the milestone branch and RC9 tag:

    git archive --format=tar.gz --output=security360-ubuntu-2026.11.28-dev.2.tar.gz 17c4d3d9d3970d2662523894d7f44a7e3caff072
    sha256sum security360-ubuntu-2026.11.28-dev.2.tar.gz

The tested archive SHA-256 is `492cf8d9b903f5cf1044829949f64270ead9e0f0155c3e08c6dcd70a7805544d`. GitHub's auto-generated archives need not be byte-identical.

For the local VM rehearsal, use an unprivileged Ubuntu account with KVM access, QEMU, genisoimage, gpgv and the Ubuntu cloud-image keyring. Supply a directory containing Canonical's Noble amd64 cloud image, matching SHA256SUMS and SHA256SUMS.gpg. The harness verifies the signature and image checksum, creates temporary disks and requires internet access for the guest installations. It does not mount host directories or forward ports.

    bash tests/rehearse_clean_vm.sh /path/to/image-directory 17c4d3d9d3970d2662523894d7f44a7e3caff072
