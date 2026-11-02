import pytest

from spectreops.safety.sandbox import Sandbox, check_command


def test_guard_blocks_destructive():
    with pytest.raises(PermissionError):
        check_command("rm -rf /")


@pytest.mark.asyncio
async def test_run_echo():
    r = await Sandbox(mode="none", timeout=15).run(["echo", "hi"])
    assert r.stdout.strip() == "hi" and r.returncode == 0
