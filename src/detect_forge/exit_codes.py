"""Detect-Forge exit-code constants.

Per Company OS §8:
- 0 (CLEAN): scan completed, no gating findings
- 1 (RESERVED): tool error, stub, or unimplemented command
- 2 (GATED): CI-gating condition met (e.g. critical finding)
"""

CLEAN = 0
RESERVED = 1
GATED = 2
