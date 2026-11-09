"""
Authentication Module for GraphQL Testing

GraphQL keeps its own typed auth triple (GRAPHQL_AUTH_TYPE/VALUE/HEADER); the
headers are built by the shared project AuthProfile builder so both paths get
the same sanitizing. The engagement identity header is merged in here (not in
the shared builder, which must stay auth-only): it is attribution, not a
credential, so it is attached unconditionally and an auth header of the same
name wins, matching append_engagement_identity.
"""

from typing import Dict

from recon.helpers.auth_profile import build_auth_headers as _build_profile_headers
from recon.helpers.auth_profile import identity_header_dict, merge_identity_headers
from recon.helpers.auth_profile import mask_auth_value  # noqa: F401  (public re-export)


def build_auth_headers(settings: dict) -> Dict[str, str]:
    """Build GraphQL request auth headers from the project settings."""
    headers = _build_profile_headers({
        'authType': settings.get('GRAPHQL_AUTH_TYPE', ''),
        'authValue': settings.get('GRAPHQL_AUTH_VALUE', ''),
        'authHeaderName': settings.get('GRAPHQL_AUTH_HEADER', ''),
    }, log_prefix='[GraphQL]')
    return merge_identity_headers(headers, identity_header_dict(settings))
