"""Layer 2 segmentation validator.

Reports which layer 2 protections a switch port enforces. Passive listening is
the default; active probes are bounded, individually selected, and gated behind
a written authorisation file.
"""

__version__ = "0.1.0"
