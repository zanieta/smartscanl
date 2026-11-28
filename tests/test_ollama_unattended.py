"""Exercise the actual Ubuntu helper without system services, network or a model download."""
import os
from pathlib import Path
import subprocess

import pytest


@pytest.mark.skipif(os.name != "posix", reason="Ubuntu installer")
def test_provisioner_without_home(tmp_path):
    install = Path(__file__).resolve().parents[1] / "install"
    helper = (install / "linux" if (install / "linux").is_dir() else install) / "install-ollama.sh"
    for name, body in {"id":"echo 0", "curl":"exit 0", "systemctl":"exit 0",
                       "ollama":'test "$HOME" = /root || exit 2; echo "$1" >> "$QA_CALLS"'}.items():
        path = tmp_path / name
        path.write_text("#!/bin/sh\n" + body + "\n")
        path.chmod(0o755)
    calls = tmp_path / "calls"
    env = {"PATH":f"{tmp_path}:/usr/bin:/bin", "QA_CALLS":str(calls), "OLLAMA_MODEL":"fixture"}
    subprocess.run(["bash",str(helper)], env=env, capture_output=True, timeout=10, check=True)
    assert calls.read_text().splitlines() == ["--version","pull","list"]
