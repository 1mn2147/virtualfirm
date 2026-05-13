from __future__ import annotations

import importlib.util
import os
import shutil

import pytest


pytestmark = [
    pytest.mark.docker_integration,
    pytest.mark.skipif(
        os.getenv("RUN_DOCKER_INTEGRATION") != "1",
        reason="Docker-only integration smoke; set RUN_DOCKER_INTEGRATION=1 in the container",
    ),
]


def test_qiling_runtime_is_available_in_docker_integration_image() -> None:
    assert importlib.util.find_spec("qiling") is not None


def test_qemu_runtime_is_available_in_docker_integration_image() -> None:
    assert shutil.which("qemu-system-arm") or shutil.which("qemu-arm")
