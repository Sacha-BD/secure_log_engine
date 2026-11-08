"""Représenter une même adresse IP de façon uniforme dans le moteur."""

from ipaddress import IPv6Address, ip_address


def normalize_ip(value: str) -> str:
    """Ignorer la zone IPv6 et ramener les adresses IPv4 mappées en IPv4."""
    address = ip_address(value)
    if isinstance(address, IPv6Address):
        mapped = address.ipv4_mapped
        if mapped is not None:
            return str(mapped)
        return str(address).partition("%")[0]
    return str(address)
