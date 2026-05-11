"""End-to-end integration test for semantic alignment.

Gated behind ``@pytest.mark.integration``; default ``pytest -q`` skips this.
Run manually with ``pytest -m integration``. This test downloads the fastembed
model on first run (~30MB) and exercises the real embedder against minimal
fixtures.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from detect_forge.stale.embeddings import EmbeddingModel, cosine_similarity


@pytest.mark.integration
def test_real_fastembed_produces_useful_similarities(tmp_path: Path) -> None:
    """Sanity-check that fastembed yields high similarity for related text and
    low similarity for unrelated text. Not asserting exact thresholds — just
    confirming the gradient is meaningful (related > unrelated)."""
    model = EmbeddingModel(cache_dir=tmp_path)
    texts = [
        "PowerShell encoded command execution detection",
        "Adversaries use PowerShell to run obfuscated scripts",
        "Apple pie recipe with cinnamon",
    ]
    [v_a, v_b, v_c] = model.embed_batch(texts)

    sim_related = cosine_similarity(v_a, v_b)  # both about PowerShell
    sim_unrelated = cosine_similarity(v_a, v_c)  # security vs cooking

    # Related texts share more semantic ground than unrelated ones.
    assert sim_related > sim_unrelated
    # Sanity bounds: cosine similarity is in [-1, 1].
    assert -1 <= sim_related <= 1
    assert -1 <= sim_unrelated <= 1
