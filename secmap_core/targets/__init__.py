"""
SecMap Target Package
Validation and safe processing of target IPs, hostnames, and CIDR ranges.
"""

from .networks import expand_network, validate_target

__all__ = ["validate_target", "expand_network"]
