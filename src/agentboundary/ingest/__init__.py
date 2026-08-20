"""Ingest -- everything a tool returns, treated as untrusted input (I2).

The public surface is deliberately narrow: :func:`ingest` and the
:class:`Envelope` it produces. There is no exported function that returns a raw
tool result, which is how FR-019 is enforced -- as an absence, not a rule.
"""

from agentboundary.ingest.envelope import Envelope, ingest
from agentboundary.ingest.normalise import NormalisationReport, normalise, strip_active_content

__all__ = ["Envelope", "NormalisationReport", "ingest", "normalise", "strip_active_content"]
