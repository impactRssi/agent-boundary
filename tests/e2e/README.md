# End-to-end tier

Drives a real agent runtime against a real broker process over the wire, with
real tool handlers pointed at throwaway fixtures. **No mocks at the boundary
under test** — an E2E test that mocks the broker is a unit test wearing a
costume.

Empty until node N-18 ships the MCP server. Recorded here rather than left as
an unexplained empty directory.

Selected by the `e2e` marker. Run with `make test-e2e`.
