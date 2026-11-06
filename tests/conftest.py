# SPDX-FileCopyrightText: 2026-present SPDX contributors
# SPDX-FileType: SOURCE
# SPDX-License-Identifier: Apache-2.0

"""Test options: slow tests run only when asked for."""

from __future__ import annotations

import pytest


def pytest_addoption(parser: pytest.Parser) -> None:
    """Add ``--real-world``, which enables the ``real_world`` tests."""
    parser.addoption(
        "--real-world",
        action="store_true",
        default=False,
        help="also run the slow tests on real-world SBOMs (run before a release)",
    )


def pytest_collection_modifyitems(
    config: pytest.Config, items: list[pytest.Item]
) -> None:
    """Skip ``real_world`` tests unless ``--real-world`` is given."""
    if config.getoption("--real-world"):
        return
    skip = pytest.mark.skip(reason="slow; run with --real-world before a release")
    for item in items:
        if "real_world" in item.keywords:
            item.add_marker(skip)
