"""Shared rate limiter instance. Imported by both main.py and payment.py."""

from slowapi import Limiter
from slowapi.util import get_remote_address

# SECURITY: Rate limiter to prevent abuse and DoS. Applied per-endpoint via decorators.
limiter = Limiter(key_func=get_remote_address)
