"""MCP SDK transport preserves the target session's identification headers."""
from contextlib import asynccontextmanager
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from recon.main_recon_modules import ai_surface_recon as mod


@pytest.mark.parametrize('transport_kind', ['http_client', 'headers', 'unsupported'])
def test_mcp_sdk_identity_headers(transport_kind):
    import mcp
    import mcp.client.streamable_http as transport

    seen = {}

    @asynccontextmanager
    async def modern(url, *, http_client=None):
        seen['purpose'] = http_client.headers.get('X-Request-Purpose')
        yield (None, None)

    @asynccontextmanager
    async def legacy(url, *, headers=None):
        seen['purpose'] = headers.get('X-Request-Purpose')
        yield (None, None, None)

    @asynccontextmanager
    async def unsupported(url):
        seen['sent'] = True
        yield (None, None)

    client = AsyncMock()
    client.initialize.return_value = SimpleNamespace(
        serverInfo=None, server_info=None, protocolVersion='test', instructions=None)
    client.list_tools.return_value = SimpleNamespace(tools=[])
    client.list_resources.return_value = SimpleNamespace(resources=[])
    client.list_prompts.return_value = SimpleNamespace(prompts=[])
    session = MagicMock()
    session.__aenter__ = AsyncMock(return_value=client)
    session.__aexit__ = AsyncMock(return_value=False)
    selected = {'http_client': modern, 'headers': legacy, 'unsupported': unsupported}[transport_kind]
    with patch.object(transport, 'streamable_http_client', selected), \
            patch.object(mcp, 'ClientSession', return_value=session):
        result = mod._mcp_enumerate('https://example.test/mcp', 1,
                                    {'X-Request-Purpose': 'Research'})
    if transport_kind == 'unsupported':
        assert result is None
        assert not seen
    else:
        assert result is not None
        assert seen == {'purpose': 'Research'}
