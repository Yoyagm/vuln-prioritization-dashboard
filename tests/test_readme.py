"""The README may not drift away from the artefact it describes.

A portfolio README whose numbers no longer match the run that produced them is
worse than no README, and it happens by accident every time someone refreshes
the data and forgets the prose. So the figures live in a generated block, and
this test regenerates it and compares.
"""

from __future__ import annotations

import json
import re

import pytest

from scripts import render_numbers
from src import paths

pytestmark = pytest.mark.skipif(
    not paths.ANALYSIS.exists(), reason="analysis.json not built"
)

README = paths.ROOT / "README.md"


@pytest.fixture(scope="module")
def readme() -> str:
    return README.read_text()


def test_the_generated_block_is_current(readme):
    analysis = json.loads(paths.ANALYSIS.read_text())
    expected = render_numbers.render(analysis)
    start = readme.index(render_numbers.BEGIN)
    end = readme.index(render_numbers.END) + len(render_numbers.END)
    assert readme[start:end] == expected, (
        "README figures are stale -- run `python -m scripts.render_numbers`"
    )


def test_no_figure_outside_the_generated_block_contradicts_the_artefact(readme):
    """Prose outside the block may still quote the headline; it must be right."""
    analysis = json.loads(paths.ANALYSIS.read_text())
    end = readme.index(render_numbers.END) + len(render_numbers.END)
    prose = readme[end:]

    positives = analysis["sla"]["count"]
    spread = {block["positives"] for block in analysis["prospective"]}
    stated = re.search(r"(\d+) to (\d+) confirmed-exploited CVEs per cutoff", prose)
    assert stated, "the prose no longer states the positive counts"
    assert (int(stated.group(1)), int(stated.group(2))) == (min(spread), max(spread))
    assert f"{positives:,}" not in prose or str(positives) in readme


def test_every_screenshot_referenced_exists(readme):
    for relative in re.findall(r"!\[[^\]]*\]\(([^)]+)\)", readme):
        assert (paths.ROOT / relative).exists(), relative


def test_the_licence_notice_is_present(readme):
    assert "neither endorsed nor certified by the NVD" in readme


def test_the_limitations_section_survives(readme):
    """The caveats are the point; a tidy-up that removes them is a regression."""
    for phrase in (
        "KEV is biased and incomplete",
        "not frozen at the cutoff",
        "Small positive counts",
    ):
        assert phrase in readme, phrase


def test_the_reproduce_block_names_real_targets(readme):
    makefile = (paths.ROOT / "Makefile").read_text()
    for target in re.findall(r"^make (\w+)", readme, flags=re.MULTILINE):
        assert re.search(rf"^{target}:", makefile, flags=re.MULTILINE), target


def test_the_test_count_in_the_prose_is_right(readme):
    """A number that only a human maintains is a number that goes stale."""
    claimed = {int(match) for match in re.findall(r"(\d+) tests", readme)}
    collected = len(
        [
            line
            for path in (paths.ROOT / "tests").glob("test_*.py")
            for line in path.read_text().splitlines()
            if line.startswith("def test_")
        ]
    )
    # Parametrised cases and class methods push the real count higher, so the
    # claim only has to be no larger than what exists.
    assert claimed, "the README stopped stating a test count"
    assert max(claimed) >= collected, (
        f"README claims {max(claimed)} tests but {collected} test functions exist"
    )
