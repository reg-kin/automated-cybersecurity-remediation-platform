"""
Automated remediation enrichment worker package.

Exports the canonical RQ entry points for backwards compatibility.
"""

from .enricher_worker import process_ai_enrichment

# Preserve old callers which may still enqueue worker.process
process = process_ai_enrichment

__all__ = [
    "process_ai_enrichment",
    "process",
]
