from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_every_raised_code_is_in_the_unified_table() -> None:
    """Every error code the AA can return must appear in docs/error-codes.md."""

    source = "\n".join(path.read_text(encoding="utf-8") for path in (ROOT / "agent-aa" / "src").rglob("*.py"))
    codes = set(re.findall(r'(?:AuthorizationDenied|VerificationError|AgentAAError|[A-Za-z]+Error)\(\s*"([A-Z][A-Z0-9_]{3,})"', source))
    assert codes, "no error codes found in agent-aa sources"
    table = (ROOT / "docs" / "error-codes.md").read_text(encoding="utf-8")
    missing = sorted(code for code in codes if f"`{code}`" not in table)
    assert not missing, f"missing from docs/error-codes.md: {missing}"
