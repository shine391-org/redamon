"""The browser User-Agent recon's own HTTP checks send.

A bare ``Mozilla/5.0`` or a truncated Chrome string (no AppleWebKit and Safari
tokens) is the first thing a WAF's bot rules match, and it earns a challenge
page instead of the site, so a challenged run reads as an empty surface. This
is the full desktop Chrome string httpx and katana already default to
(HTTPX_CUSTOM_HEADERS / KATANA_CUSTOM_HEADERS in recon/project_settings.py; a
test keeps the two equal).

The self-identifying ``RedAmon-*`` agents (js_recon, takeover, the cache
scanner) are deliberate and do not use it.
"""

DEFAULT_BROWSER_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)
