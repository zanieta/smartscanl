#!/bin/bash
# Ubuntu-only. Two clean, private guests; no host filesystem sharing or incoming port forwards.
set -euo pipefail
umask 077
[[ $# == 2 && $(id -u) != 0 ]] || { echo "Usage (unprivileged): bash $0 VERIFIED_IMAGE_DIR CANDIDATE_COMMIT" >&2; exit 2; }
repo=$(git -C "$(dirname "$0")" rev-parse --show-toplevel)
candidate=$(git -C "$repo" rev-parse --verify --end-of-options "$2^{commit}")
previous=$(git -C "$repo" rev-parse 'v2026.10.20-rc9^{commit}')
[[ $previous == c6088a62c3a5ee781eb90954446341def410c381 ]] || { echo "Unexpected RC9 commit" >&2; exit 1; }
image_dir=$(realpath -e -- "$1")
image=noble-server-cloudimg-amd64.img
(
    cd "$image_dir"
    gpgv --keyring /usr/share/keyrings/ubuntu-cloudimage-keyring.gpg SHA256SUMS.gpg SHA256SUMS
    grep -E '^[0-9a-f]{64} [ *]noble-server-cloudimg-amd64\.img$' SHA256SUMS | sha256sum --strict --check
)
work=$(mktemp -d "${TMPDIR:-/tmp}/security360-acceptance.XXXXXXXX")
trap 'rm -rf -- "$work"' EXIT
mkdir "$work/seed"
git -C "$repo" archive --format=tar.gz --output="$work/seed/candidate.tgz" "$candidate"
git -C "$repo" archive --format=tar.gz --output="$work/seed/previous.tgz" "$previous"
cp "$(dirname "$0")/ubuntu_vm_guest.sh" "$work/seed/guest.sh"
cd "$work"
sha256sum seed/candidate.tgz
for mode in fresh upgrade; do
    printf 'instance-id: %s-%s\nlocal-hostname: security360-qa-%s\n' "$(basename "$work")" "$mode" "$mode" >seed/meta-data
    printf '%s\n' '#cloud-config' 'ssh_pwauth: false' 'disable_root: true' 'runcmd:' \
        '  - [mkdir, -p, /run/security360-qa]' \
        '  - [mount, -o, "ro,nosuid,nodev", "LABEL=cidata", /run/security360-qa]' \
        "  - [bash, /run/security360-qa/guest.sh, $mode]" >seed/user-data
    genisoimage -quiet -output "$mode.iso" -volid cidata -joliet -rock seed
    qemu-img create -q -f qcow2 -F qcow2 -b "$image_dir/$image" "$mode.img" 24G
    echo "Testing $mode in a clean Ubuntu guest..."
    timeout 48m qemu-system-x86_64 -accel kvm -cpu host -smp 2 -m 2400 -nodefaults \
        -drive "file=$mode.img,if=virtio,format=qcow2" -drive "file=$mode.iso,media=cdrom,readonly=on" \
        -nic user,model=virtio-net-pci -display none -serial "file:$mode.log" -monitor none -no-reboot
    grep -F "SECURITY360-QA $mode PASS installed version" "$mode.log" || {
        grep -F "SECURITY360-QA $mode " "$mode.log" | tail -4 >&2 || true
        exit 1
    }
done
