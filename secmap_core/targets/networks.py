"""
SecMap Target & Network Processing Module
Validates target IP addresses, hostnames, and CIDR ranges using standard library ipaddress module.
Phase 9 implementation.
"""

import ipaddress
import re

HOSTNAME_REGEX = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$"
)


def validate_target(target: str) -> tuple[bool, str]:
    """
    Validate if a target string is a valid IPv4, IPv6, Hostname, or CIDR network.

    Args:
        target (str): Target string to validate.

    Returns:
        tuple[bool, str]: (is_valid, target_type) where target_type is 'ipv4', 'ipv6', 'cidr', 'hostname', or 'invalid'.
    """
    if not target or not isinstance(target, str):
        return False, "invalid"

    target_str = target.strip()
    if not target_str:
        return False, "invalid"

    # Check IPv4 or IPv6 single address
    try:
        ip_obj = ipaddress.ip_address(target_str)
        return True, "ipv4" if ip_obj.version == 4 else "ipv6"
    except ValueError:
        pass

    # Check CIDR network (e.g. 192.168.1.0/24 or 2001:db8::/64)
    if "/" in target_str:
        try:
            ipaddress.ip_network(target_str, strict=False)
            return True, "cidr"
        except ValueError:
            return False, "invalid"

    # Check Hostname
    if target_str.lower() == "localhost" or HOSTNAME_REGEX.match(target_str):
        return True, "hostname"

    return False, "invalid"


def expand_network(network: str, max_hosts: int = 4096) -> list[str]:
    """
    Safely expand a CIDR network target into individual IP strings up to max_hosts limit.

    Args:
        network (str): CIDR target string (e.g., '192.168.1.0/24').
        max_hosts (int): Maximum allowed host expansion count (default: 4096).

    Returns:
        list[str]: List of IP address strings.

    Raises:
        ValueError: If network syntax is invalid or network size exceeds max_hosts.
    """
    is_valid, ttype = validate_target(network)
    if not is_valid:
        raise ValueError(f"SecMap Target Error: Invalid network target '{network}'.")

    if ttype in ("ipv4", "ipv6", "hostname"):
        return [network.strip()]

    try:
        net_obj = ipaddress.ip_network(network.strip(), strict=False)
    except ValueError as e:
        raise ValueError(f"SecMap Target Error: Invalid CIDR network '{network}': {str(e)}")

    num_hosts = net_obj.num_addresses
    if num_hosts > max_hosts:
        raise ValueError(
            f"SecMap Target Error: CIDR range '{network}' contains {num_hosts} hosts, which exceeds "
            f"the safe expansion limit of {max_hosts} hosts. Pass the CIDR directly to Nmap or reduce the network size."
        )

    return [str(ip) for ip in net_obj.hosts()]
