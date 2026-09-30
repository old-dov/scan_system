"""Windows PowerShell exit codes for failed Defender-style actions."""

import sys

import pytest

import scanner_windows as sw


@pytest.mark.skipif(sys.platform != "win32", reason="Windows PowerShell required")
def test_nonterminating_error_cannot_be_masked_by_success_marker():
    ok, _ = sw.run_powershell(
        "$ErrorActionPreference = 'Stop'; Write-Error 'simulated failure'; 'success_marker'",
        timeout=15,
    )
    assert not ok
