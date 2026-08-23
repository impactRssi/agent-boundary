"""GUI tier (N-45): what an operator can see about what is currently granted.

An operator who cannot see what is leased cannot revoke it, so a lease nobody
can see is an unbounded one in every way that matters until it happens to
expire. These tests assert on the rendered page in a real browser, because that
is what someone actually looks at when deciding whether the agent still has
access to a credential directory.

The second class is the more important one. This page displays leases; it must
not be able to create, extend or revoke one. The refusal ledger's failure mode
-- a list that reads like a to-do list and invites bulk approval -- has an exact
analogue here: a row with a button beside it. There is no button, and the tests
below are what make that an assertion rather than a convention.
"""

from __future__ import annotations

import pytest
from playwright.sync_api import Page

pytestmark = pytest.mark.gui


class TestWhatIsGrantedIsVisible:
    def test_every_lease_in_the_store_is_on_the_page(self, viewer: Page) -> None:
        assert viewer.locator("[data-testid='lease']").count() == 3

    def test_an_active_lease_states_the_time_remaining(self, viewer: Page) -> None:
        """ "expires at 1755993600" is not actionable; "2.00 days remaining" is."""
        active = viewer.locator("[data-testid='lease'][data-state='active']")
        assert active.count() == 1
        assert "2.00 days remaining" in active.locator("[data-testid='lease-state']").inner_text()

    def test_an_expired_lease_says_so_and_says_how_long_ago(self, viewer: Page) -> None:
        expired = viewer.locator("[data-testid='lease'][data-state='expired']")
        assert expired.count() == 2
        texts = expired.locator("[data-testid='lease-state']").all_inner_texts()
        assert all("expired" in text and "ago" in text for text in texts)

    def test_active_and_expired_are_distinguishable_without_reading_text(
        self, viewer: Page
    ) -> None:
        active = viewer.locator("[data-testid='lease'][data-state='active']").first
        expired = viewer.locator("[data-testid='lease'][data-state='expired']").first
        assert active.evaluate("n => getComputedStyle(n).borderLeftColor") != expired.evaluate(
            "n => getComputedStyle(n).borderLeftColor"
        )

    def test_each_lease_shows_who_granted_it_and_why(self, viewer: Page) -> None:
        """A grant with no visible reason is indistinguishable at review time
        from a grant made in error, which is what the reason exists to prevent."""
        first = viewer.locator("[data-testid='lease']").first
        assert (
            "operator@example.test"
            in first.locator("[data-testid='lease-attribution']").inner_text()
        )
        assert "nightly automation" in first.locator("[data-testid='lease-reason']").inner_text()

    def test_each_lease_shows_its_sensitivity_class(self, viewer: Page) -> None:
        classes = viewer.locator("[data-testid='lease-attribution']").all_inner_texts()
        assert any("credential" in text for text in classes)
        assert any("routine" in text for text in classes)

    def test_an_unpinned_lease_says_it_applies_to_every_task(self, viewer: Page) -> None:
        """The widest thing a lease can express, said out loud on the page."""
        attributions = viewer.locator("[data-testid='lease-attribution']").all_inner_texts()
        assert all("every task" in text for text in attributions)

    def test_the_summary_counts_what_is_in_force_now(self, viewer: Page) -> None:
        summary = viewer.locator("#lease-summary").inner_text().lower()
        assert "in force now" in summary
        assert "rotation owed" in summary

    def test_an_expired_credential_lease_shows_its_rotation_advisory(self, viewer: Page) -> None:
        advisories = viewer.locator("[data-testid='advisory']")
        assert advisories.count() == 1
        text = advisories.first.inner_text()
        assert "Rotate every secret stored under" in text
        assert "not evidence that nothing was taken" in text

    def test_a_routine_lease_owes_no_rotation_advice(self, viewer: Page) -> None:
        """Two leases expired; only the credential-class one owes an advisory.
        A page that advised on everything would be one an operator filters."""
        assert viewer.locator("[data-testid='advisory']").count() == 1


class TestTheViewerCannotGrantExtendOrRevoke:
    def test_the_page_still_exposes_no_form_input_or_button(self, viewer: Page) -> None:
        """The leases section added rows. It must not have added an affordance."""
        for selector in ("form", "input", "button", "textarea", "select", "[contenteditable]"):
            assert viewer.locator(selector).count() == 0, selector

    def test_no_lease_row_is_clickable(self, viewer: Page) -> None:
        clickable = viewer.evaluate(
            """() => [...document.querySelectorAll("[data-testid='lease']")]
                 .filter(n => n.onclick || n.querySelector('a, button, [role=button]')).length"""
        )
        assert clickable == 0

    def test_the_page_states_that_it_cannot_grant(self, viewer: Page) -> None:
        notice = viewer.locator("[data-testid='lease-notice']").inner_text()
        assert "cannot create, extend or revoke" in notice
        assert "granted out of band" in notice

    def test_the_page_states_what_a_lease_costs_while_it_runs(self, viewer: Page) -> None:
        notice = viewer.locator("[data-testid='lease-notice']").inner_text()
        assert "the invariant it widens does not hold for its subject" in notice

    def test_the_page_says_how_revocation_actually_works(self, viewer: Page) -> None:
        """There is no revoke control, so the page has to say what to do instead."""
        notice = viewer.locator("[data-testid='lease-notice']").inner_text()
        assert "delete the lease's line" in notice.lower()

    @pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE"])
    def test_the_lease_route_implements_no_write_method(
        self, viewer: Page, viewer_url: str, method: str
    ) -> None:
        """Not a guarded 403 -- no route at all. A viewer that could mint a lease
        would be a second write path into the store, reachable over HTTP."""
        status = viewer.evaluate(
            """async ([url, method]) => {
                const response = await fetch(url + 'leases.json', { method });
                return response.status;
            }""",
            [viewer_url, method],
        )
        assert status in (405, 501), f"{method} returned {status}"

    def test_the_lease_json_carries_no_field_that_could_grant(
        self, viewer: Page, viewer_url: str
    ) -> None:
        names = viewer.evaluate(
            """async (url) => {
                const payload = await (await fetch(url + 'leases.json')).json();
                return payload.leases.flatMap(lease => Object.keys(lease));
            }""",
            viewer_url,
        )
        offending = [
            name
            for name in names
            for word in ("approve", "extend", "renew", "revoke", "index")
            if word in name.lower()
        ]
        assert not offending, offending


class TestRenderingLeasesIsNotAnInjectionPath:
    def test_a_lease_subject_is_rendered_as_text(self, viewer: Page) -> None:
        """A lease subject is operator-typed, but the page renders it beside a
        trace full of attacker strings and uses the same textContent path for
        both. One rendering rule, no exception to forget."""
        scripts_with_src = viewer.evaluate(
            "() => [...document.querySelectorAll('script')].filter(s => s.src).length"
        )
        assert scripts_with_src == 0
        assert viewer.evaluate("() => document.querySelectorAll('img, iframe').length") == 0
