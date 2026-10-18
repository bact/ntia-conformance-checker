# SPDX-FileCopyrightText: 2026-present SPDX contributors
# SPDX-FileType: SOURCE
# SPDX-License-Identifier: Apache-2.0

"""The slow real-world tests run only with ``--real-world``."""

from __future__ import annotations

from pathlib import Path

import pytest

pytest_plugins = ["pytester"]


@pytest.mark.parametrize(
    ("args", "outcome"),
    [([], {"passed": 1, "skipped": 1}), (["--real-world"], {"passed": 2})],
    ids=["default", "opted-in"],
)
def test_real_world_marker_is_opt_in(
    pytester: pytest.Pytester, args: list[str], outcome: dict[str, int]
) -> None:
    pytester.makeconftest((Path(__file__).parent / "conftest.py").read_text("utf-8"))
    pytester.makepyfile("""
        import pytest

        def test_fast():
            pass

        @pytest.mark.real_world
        def test_slow():
            pass
        """)
    pytester.runpytest(*args).assert_outcomes(**outcome)
