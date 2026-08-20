"""GUI tier (N-22): what an operator can actually see during an incident.

These assert on the rendered page in a real browser, not on the JSON behind it.
An operator does not read JSON Lines at 3am; they read this.
"""

from __future__ import annotations

import pytest
from playwright.sync_api import Page

pytestmark = pytest.mark.gui


class TestRefusalsAreVisiblyRefused:
    def test_every_refused_call_reads_as_refused(self, viewer: Page) -> None:
        refused = viewer.locator("[data-testid='record'][data-outcome='refuse']")
        assert refused.count() == 4
        for index in range(refused.count()):
            assert refused.nth(index).locator("[data-testid='verdict']").inner_text() == "REFUSED"

    def test_each_refusal_shows_its_machine_readable_reason(self, viewer: Page) -> None:
        """The reason is what an operator triages on; it must be on screen."""
        reasons = viewer.locator("[data-testid='reason']").all_inner_texts()
        assert "path_outside_root" in reasons
        assert "tool_not_in_scope" in reasons
        assert "approval_mismatch" in reasons
        assert "budget_exhausted" in reasons

    def test_authorised_and_refused_are_distinguishable_without_reading_text(
        self, viewer: Page
    ) -> None:
        authorised = viewer.locator("[data-testid='record'][data-outcome='authorise']").first
        refused = viewer.locator("[data-testid='record'][data-outcome='refuse']").first
        assert authorised.evaluate("n => getComputedStyle(n).borderLeftColor") != refused.evaluate(
            "n => getComputedStyle(n).borderLeftColor"
        )


class TestDistinctStates:
    def test_budget_exhaustion_and_pending_approval_read_differently(self, viewer: Page) -> None:
        """An operator must not have to guess which control stopped the task."""
        budget = viewer.locator("[data-reason='budget_exhausted']")
        approval = viewer.locator("[data-reason='approval_mismatch']")
        assert budget.count() == 1
        assert approval.count() == 1
        assert (
            budget.locator("[data-testid='reason']").inner_text()
            != approval.locator("[data-testid='reason']").inner_text()
        )

    def test_the_summary_reports_counts_per_reason(self, viewer: Page) -> None:
        # inner_text returns rendered text, and the labels are uppercased by CSS.
        summary = viewer.locator("#summary").inner_text().lower()
        assert "calls" in summary
        assert "refused" in summary
        assert "path_outside_root" in summary


class TestAttribution:
    def test_every_record_shows_its_task_and_result_status(self, viewer: Page) -> None:
        attributions = viewer.locator("[data-testid='attribution']").all_inner_texts()
        assert len(attributions) == 6
        assert all("gui-demo" in text for text in attributions)

    def test_the_decision_path_is_visible_not_just_the_verdict(self, viewer: Page) -> None:
        """Reconstructing *why* is the point; the verdict alone is not enough."""
        first_refusal = viewer.locator("[data-testid='record'][data-outcome='refuse']").first
        checks = first_refusal.locator("[data-testid='checks'] li").all_inner_texts()
        assert any("scope" in check for check in checks)
        assert any("path_confinement" in check or "outside root" in check for check in checks)

    def test_post_validation_arguments_are_shown(self, viewer: Page) -> None:
        assert "runbook.md" in viewer.locator("[data-testid='arguments']").first.inner_text()


class TestTheViewerCannotMutateATrace:
    def test_the_page_exposes_no_form_input_or_button(self, viewer: Page) -> None:
        for selector in ("form", "input", "button", "textarea", "select", "[contenteditable]"):
            assert viewer.locator(selector).count() == 0, selector

    def test_no_record_text_is_editable(self, viewer: Page) -> None:
        editable = viewer.evaluate(
            "() => [...document.querySelectorAll('*')].filter(n => n.isContentEditable).length"
        )
        assert editable == 0

    @pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE"])
    def test_the_server_implements_no_write_method(
        self, viewer: Page, viewer_url: str, method: str
    ) -> None:
        """Not a guarded 403 -- no route at all. The absence is the control."""
        status = viewer.evaluate(
            """async ([url, method]) => {
                const response = await fetch(url + 'trace.json', { method });
                return response.status;
            }""",
            [viewer_url, method],
        )
        assert status in (405, 501), f"{method} returned {status}"


class TestRenderingIsNotAnInjectionPath:
    def test_attacker_authored_strings_are_rendered_as_text(self, viewer: Page) -> None:
        """A trace is full of attacker strings; rendering one as markup would
        turn the viewer into the exfiltration path the broker just refused."""
        injected = viewer.evaluate(
            "() => document.querySelectorAll('script:not([data-app]), img, iframe').length"
        )
        # The page's own inline script is the only script, and it has no src.
        scripts_with_src = viewer.evaluate(
            "() => [...document.querySelectorAll('script')].filter(s => s.src).length"
        )
        assert scripts_with_src == 0
        assert injected <= 1
