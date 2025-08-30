from __future__ import annotations
import hashlib
from typing import Dict

def calculate_sha256(data: bytes) -> bytes:
    """ Calculate SHA-256 hash and return as hex bytes. """
    h = hashlib.sha256()
    h.update(data)
    return h.hexdigest()
