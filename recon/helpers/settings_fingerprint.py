"""Deterministic hashes for configuration mixed with live runtime helpers.

Never stringify arbitrary objects (repr includes addresses and may expose keys).
Only KeyRotator has an explicit immutable configuration identity. Ordinary JSON
settings retain their historical encoding/hash for checkpoint compatibility.
"""
from __future__ import annotations

import hashlib
import json


def _runtime_configuration(value):
    cls = type(value)
    if (cls.__name__ == 'KeyRotator'
            and cls.__module__ in {'helpers.key_rotation', 'recon.helpers.key_rotation'}):
        # Explicit class-bound token. Do not inspect attributes of an
        # arbitrary same-named object, and never serialize its live list.
        return {'__key_rotator_config_v1__': value.configuration_fingerprint}
    raise TypeError(f'Unsupported runtime settings value: {cls.__name__}')


def settings_fingerprint(settings, *, compact=False):
    """Hash effective settings without serializing mutable helper internals.

    Every ``*_KEY_ROTATOR`` key is replaced by its stable configuration token,
    so the historical full-settings JSON digest stays identical to the value the
    old loader's JSON-compatible settings produced. Rotation counters and
    provider-rejection state are not configuration. Unknown runtime objects
    fail closed; they are never stringified/repr'd. No plaintext credentials or
    settings payload are returned.
    """
    encoded = json.dumps(settings or {}, sort_keys=True,
                         default=_runtime_configuration,
                         separators=(',', ':') if compact else None).encode()
    return hashlib.sha256(encoded).hexdigest()
