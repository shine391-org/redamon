"""
RedAmon - CVE Lookup Helpers
============================
Functions for looking up CVEs from NVD and Vulners APIs based on detected technologies.
"""

import operator
import re
import time
import requests
from datetime import datetime
from typing import Dict, List, Optional, Tuple


# =============================================================================
# API URLs
# =============================================================================

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
VULNERS_API_URL = "https://vulners.com/api/v3/burp/software/"


# =============================================================================
# CPE Mappings for Common Technologies
# =============================================================================

CPE_MAPPINGS = {
    # Web Servers
    "nginx": ("f5", "nginx"),
    "apache": ("apache", "http_server"),
    "iis": ("microsoft", "internet_information_services"),
    "tomcat": ("apache", "tomcat"),
    "lighttpd": ("lighttpd", "lighttpd"),
    "caddy": ("caddyserver", "caddy"),
    "litespeed": ("litespeedtech", "litespeed_web_server"),
    "cherokee": ("cherokee-project", "cherokee"),
    "gunicorn": ("gunicorn", "gunicorn"),
    "uvicorn": ("encode", "uvicorn"),
    "traefik": ("traefik", "traefik"),
    "envoy": ("envoyproxy", "envoy"),
    "openresty": ("openresty", "openresty"),
    "deno": ("deno", "deno"),
    "tengine": ("alibaba", "tengine"),
    # Languages/Runtimes
    "php": ("php", "php"),
    "python": ("python", "python"),
    "node.js": ("nodejs", "node.js"),
    "ruby": ("ruby-lang", "ruby"),
    "perl": ("perl", "perl"),
    "go": ("golang", "go"),
    # Databases
    "mysql": ("oracle", "mysql"),
    "mariadb": ("mariadb", "mariadb"),
    "postgresql": ("postgresql", "postgresql"),
    "mongodb": ("mongodb", "mongodb"),
    "redis": ("redis", "redis"),
    "elasticsearch": ("elastic", "elasticsearch"),
    "couchdb": ("apache", "couchdb"),
    "memcached": ("memcached", "memcached"),
    "sqlite": ("sqlite", "sqlite"),
    "solr": ("apache", "solr"),
    "adminer": ("adminer", "adminer"),
    # CMS
    "wordpress": ("wordpress", "wordpress"),
    "drupal": ("drupal", "drupal"),
    "joomla": ("joomla", "joomla"),
    "magento": ("adobe", "magento"),
    "ghost": ("ghost", "ghost"),
    "typo3": ("typo3", "typo3"),
    "concrete cms": ("concretecms", "concrete_cms"),
    "craft cms": ("craftcms", "craft_cms"),
    "strapi": ("strapi", "strapi"),
    "umbraco": ("umbraco", "umbraco_cms"),
    "adobe experience manager": ("adobe", "experience_manager"),
    "sitecore": ("sitecore", "experience_platform"),
    "dnn": ("dnnsoftware", "dotnetnuke"),
    "kentico": ("kentico", "kentico"),
    # Web Frameworks
    "django": ("djangoproject", "django"),
    "laravel": ("laravel", "laravel"),
    "spring": ("vmware", "spring_framework"),
    "flask": ("palletsprojects", "flask"),
    "express": ("expressjs", "express"),
    "rails": ("rubyonrails", "rails"),
    "codeigniter": ("codeigniter", "codeigniter"),
    "symfony": ("sensiolabs", "symfony"),
    "cakephp": ("cakephp", "cakephp"),
    "yii": ("yiiframework", "yii"),
    "nuxt.js": ("nuxt", "nuxt.js"),
    "struts": ("apache", "struts"),
    "coldfusion": ("adobe", "coldfusion"),
    # JavaScript Frameworks & Libraries
    "jquery": ("jquery", "jquery"),
    "angular": ("angular", "angular"),
    "react": ("facebook", "react"),
    "vue": ("vuejs", "vue.js"),
    "bootstrap": ("getbootstrap", "bootstrap"),
    "next.js": ("vercel", "next.js"),
    "moment.js": ("momentjs", "moment"),
    "lodash": ("lodash", "lodash"),
    "handlebars": ("handlebarsjs", "handlebars"),
    "ember.js": ("emberjs", "ember.js"),
    "backbone.js": ("backbonejs", "backbone.js"),
    "dojo": ("dojotoolkit", "dojo"),
    "ckeditor": ("ckeditor", "ckeditor"),
    "tinymce": ("tiny", "tinymce"),
    "prototype": ("prototypejs", "prototype"),
    # E-commerce
    "prestashop": ("prestashop", "prestashop"),
    "opencart": ("opencart", "opencart"),
    "oscommerce": ("oscommerce", "oscommerce"),
    "zen cart": ("zen-cart", "zen_cart"),
    "woocommerce": ("automattic", "woocommerce"),
    # Message Boards / Community
    "discourse": ("discourse", "discourse"),
    "phpbb": ("phpbb", "phpbb"),
    "vbulletin": ("vbulletin", "vbulletin"),
    "mybb": ("mybb", "mybb"),
    "flarum": ("flarum", "flarum"),
    "nodebb": ("nodebb", "nodebb"),
    "mastodon": ("joinmastodon", "mastodon"),
    "mattermost": ("mattermost", "mattermost_server"),
    # Wikis
    "mediawiki": ("mediawiki", "mediawiki"),
    "confluence": ("atlassian", "confluence_server"),
    "dokuwiki": ("dokuwiki", "dokuwiki"),
    "xwiki": ("xwiki", "xwiki"),
    # Mail Servers / Webmail
    "postfix": ("postfix", "postfix"),
    "exim": ("exim", "exim"),
    "dovecot": ("dovecot", "dovecot"),
    "zimbra": ("synacor", "zimbra_collaboration_suite"),
    "squirrelmail": ("squirrelmail", "squirrelmail"),
    # DNS
    "bind": ("isc", "bind"),
    # FTP
    "proftpd": ("proftpd", "proftpd"),
    "vsftpd": ("vsftpd_project", "vsftpd"),
    "pureftpd": ("pureftpd", "pure-ftpd"),
    # Security / Proxies / Network
    "openssh": ("openbsd", "openssh"),
    "openssl": ("openssl", "openssl"),
    "squid": ("squid-cache", "squid"),
    "haproxy": ("haproxy", "haproxy"),
    "varnish": ("varnish-software", "varnish_cache"),
    "kong": ("konghq", "kong_gateway"),
    "f5 big-ip": ("f5", "big-ip_access_policy_manager"),
    "pulse secure": ("pulsesecure", "pulse_connect_secure"),
    # CI/CD, DevOps & Issue Trackers
    "grafana": ("grafana", "grafana"),
    "jenkins": ("jenkins", "jenkins"),
    "gitlab": ("gitlab", "gitlab"),
    "sonarqube": ("sonarsource", "sonarqube"),
    "nexus": ("sonatype", "nexus_repository_manager"),
    "rabbitmq": ("vmware", "rabbitmq"),
    "kafka": ("apache", "kafka"),
    "zookeeper": ("apache", "zookeeper"),
    "jira": ("atlassian", "jira"),
    "bitbucket": ("atlassian", "bitbucket"),
    "bugzilla": ("mozilla", "bugzilla"),
    "redmine": ("redmine", "redmine"),
    "gitea": ("gitea", "gitea"),
    "teamcity": ("jetbrains", "teamcity"),
    "artifactory": ("jfrog", "artifactory"),
    # Java Application Servers
    "jetty": ("eclipse", "jetty"),
    "wildfly": ("redhat", "wildfly"),
    "passenger": ("phusion", "passenger"),
    # Hosting Panels
    "cpanel": ("cpanel", "cpanel"),
    "plesk": ("plesk", "plesk"),
    "directadmin": ("directadmin", "directadmin"),
    # Other
    "phpmyadmin": ("phpmyadmin", "phpmyadmin"),
    "webmin": ("webmin", "webmin"),
    "roundcube": ("roundcube", "webmail"),
    "minio": ("minio", "minio"),
}


# =============================================================================
# Technology Parsing Utilities
# =============================================================================

def _extract_semver(version: str) -> Optional[str]:
    """
    Extract the semantic version from a version string,
    stripping distro suffixes, patch identifiers, etc.

    Examples:
        "8.1.2-1ubuntu2.14" → "8.1.2"
        "2.4.49"            → "2.4.49"
        "1.19.0p1"          → "1.19.0"
        "9.0.65"            → "9.0.65"
        "8.9p1"             → "8.9"
        "10"                → "10"
        "v5.22.1"           → "5.22.1"
        ""                  → None
    """
    if not version:
        return None
    # Strip leading 'v' prefix (e.g., "v5.22.1" → "5.22.1")
    version = re.sub(r'^[vV]', '', version)
    # Try multi-part version first (x.y or x.y.z)
    match = re.match(r'(\d+(?:\.\d+)+)', version)
    if match:
        return match.group(1)
    # Fall back to single major version (e.g. "10" from "IIS/10")
    match = re.match(r'(\d+)', version)
    return match.group(1) if match else None


def split_server_header(header: str) -> List[str]:
    """
    Split a compound HTTP Server header into individual product tokens.

    Server headers can contain multiple products separated by spaces, but
    multi-word names like "Apache Tomcat" complicate naive splitting.

    Strategy: use regex to find all "Name/Version" or "Name_Version" tokens,
    then also catch standalone "(qualifier)" groups and skip them.

    Examples:
        "Apache/2.4.49 (Unix) OpenSSL/1.1.1l PHP/8.1.2-1ubuntu2.14"
            → ["Apache/2.4.49", "OpenSSL/1.1.1l", "PHP/8.1.2-1ubuntu2.14"]

        "Apache/2.4.49 (Unix)"
            → ["Apache/2.4.49"]

        "nginx/1.18.0 (Ubuntu)"
            → ["nginx/1.18.0"]

        "Apache Tomcat/9.0.65"
            → ["Apache Tomcat/9.0.65"]

        "OpenSSH_8.9p1 Ubuntu-3ubuntu0.4"
            → ["OpenSSH_8.9p1"]

        "Nginx:1.19.0"
            → ["Nginx:1.19.0"]

        "jQuery"
            → ["jQuery"]
    """
    if not header or not header.strip():
        return []

    # Also match underscore-joined tokens like "OpenSSH_8.9p1"
    # but NOT "mod_wsgi/4.6.8" (has slash, so handled by slash_pattern)
    underscore_pattern = re.compile(
        r'([A-Za-z][A-Za-z0-9-]*_\d[\w.]*)'
    )

    products = []
    remaining = header.strip()

    # First extract underscore-joined tokens WITHOUT a slash/colon after them
    for m in underscore_pattern.finditer(remaining):
        token = m.group(1)
        end_pos = m.end()
        # Skip if this token is followed by / or : (it's part of a slash-product)
        if end_pos < len(remaining) and remaining[end_pos] in '/:':
            continue
        products.append(token)

    if products:
        # Remove extracted tokens from remaining
        for p in products:
            remaining = remaining.replace(p, ' ')

    # Now find slash/colon-delimited products in the remaining string
    # Match: "Name/version" or "Multi-Word_Name/version"
    # Name can contain letters, digits, spaces, hyphens, underscores
    # Version can optionally start with 'v' prefix (e.g., "Perl/v5.22.1")
    slash_pattern = re.compile(
        r'([A-Za-z][A-Za-z0-9 _-]*?)\s*[/:]\s*(v?\d[\w._-]*)'
    )
    for m in slash_pattern.finditer(remaining):
        full = m.group(0).strip()
        products.append(full)

    # If nothing was found with delimiters, return the original string as-is
    if not products:
        return [header.strip()]

    return products


def parse_technology_string(tech: str) -> Tuple[str, Optional[str]]:
    """
    Parse a SINGLE technology string into (name, version).

    For compound server headers with multiple products (e.g.,
    "Apache/2.4.49 (Unix) OpenSSL/1.1.1l"), use split_server_header()
    first to split into individual tokens, then parse each one.

    Handles formats:
        "Nginx:1.19.0"                          → ("nginx", "1.19.0")
        "Apache/2.4.49 (Unix)"                  → ("apache", "2.4.49")
        "PHP/8.1.2-1ubuntu2.14"                 → ("php", "8.1.2")
        "OpenSSH_8.9p1 Ubuntu-3ubuntu0.4"       → ("openssh", "8.9")
        "Apache Tomcat/9.0.65"                  → ("apache tomcat", "9.0.65")
        "jQuery"                                → ("jquery", None)
        "Microsoft-IIS/10.0"                    → ("microsoft-iis", "10.0")
        "mini_httpd/1.30"                       → ("mini_httpd", "1.30")
    """
    tech = tech.strip()
    if not tech:
        return "", None

    # Skip strings that are just a bare version number (no product name)
    if re.match(r'^\d+[\d.]*$', tech):
        return "", None

    # Handle parenthesized version (e.g., "Jetty(9.4.44.v20210927)")
    paren_match = re.match(r'^([A-Za-z][A-Za-z0-9 _-]*?)\((.+?)\)$', tech)
    if paren_match:
        name = paren_match.group(1).strip().lower()
        version = _extract_semver(paren_match.group(2))
        return name, version

    # Handle underscore-joined name_version (e.g., "OpenSSH_8.9p1 Ubuntu-3")
    # But NOT "name_name/version" patterns like "mini_httpd/1.30"
    underscore_match = re.match(r'^([A-Za-z][A-Za-z0-9-]*)_(\d[\w.]*)', tech)
    if underscore_match and '/' not in tech and ':' not in tech:
        name = underscore_match.group(1).lower()
        version = _extract_semver(underscore_match.group(2))
        return name, version

    # Prefer colon and slash over space — they are explicit version delimiters.
    # Colon: Wappalyzer format "Name:version" — split on first occurrence
    # Slash: Server header format "Name/version" — split on first occurrence
    #   This correctly handles "Apache/2.4.49 (Unix) OpenSSL/1.1.1l" → ("apache", "2.4.49")
    #   For multi-word names like "Apache Tomcat/9.0.65", first split gives the right result too
    for delimiter in [':', '/']:
        if delimiter in tech:
            parts = tech.split(delimiter, 1)
            name = parts[0].strip().lower()
            raw_version = parts[1].strip() if len(parts) > 1 else None
            if raw_version:
                # Remove everything from the first space onward
                # (handles "2.4.49 (Unix) OpenSSL/1.1.1l" → "2.4.49")
                raw_version = raw_version.split()[0]
            version = _extract_semver(raw_version) if raw_version else None
            # If what we extracted as "version" doesn't look numeric, it's not a real version
            # Return just the name part (e.g., "MinIO/RELEASE.2023..." → "minio", None)
            if version is None and raw_version and not re.match(r'\d', raw_version):
                return name, None
            return name, version

    # Space delimiter — check if the LAST token looks like a version
    if ' ' in tech:
        tokens = tech.split()
        last_token = tokens[-1]
        if re.match(r'\d', last_token):
            # Last token starts with digit → treat as version, rest is the name
            name = ' '.join(tokens[:-1]).lower()
            version = _extract_semver(last_token)
            return name, version
        # Multi-word name without version (e.g., "Apache Tomcat")
        return tech.lower(), None

    return tech.lower(), None


def parse_httpx_technology(tech: str) -> Tuple[str, Optional[str]]:
    """Parse an httpx / Wappalyzer label, "Name:version" or "Name", into (name, version).

    Only a colon introduces a version in these labels; a "/" or a number is part
    of the name ("HTTP/3", "Microsoft 365"), which is how the graph writer reads
    the same label (http_mixin). parse_technology_string also splits on "/" and
    on a trailing number, right for a Server header but here it turned the
    protocol "HTTP/3" into the product "http" at version 3.
    """
    tech = tech.strip()
    if ":" not in tech:
        return tech.lower(), None
    return parse_technology_string(tech)


#: Words nmap and the fingerprinters put after a product name without making it
#: another product: "Exim smtpd", "PostgreSQL DB", "Squid http proxy", "TYPO3 CMS".
#: vuln_mixin._TECH_DESCRIPTOR_WORDS strips the same words to link a CVE to a node.
_DESCRIPTOR_WORDS = frozenset({
    "http", "https", "httpd", "server", "web", "webserver", "daemon", "smtpd",
    "ftpd", "sshd", "imapd", "pop3d", "smbd", "proxy", "accelerator", "framework",
    "db", "database", "app", "application", "api", "net", "cms",
})
#: "rest" alone is part of a name: "Django REST framework" is not Django.
_DESCRIPTOR_PHRASES = (("rest", "api"), ("key-value", "store"))
#: The descriptors that name the daemon rather than the product, which a CVE's
#: text seldom repeats ("Dropbear sshd", "Samba smbd"). "HTTP Server" and the
#: like stay: "IBM HTTP Server" searched as "ibm" would return every IBM CVE.
_SERVICE_WORDS = frozenset({"httpd", "smtpd", "ftpd", "sshd", "imapd", "pop3d", "smbd",
                            "daemon", "db", "database"})


def _strip_descriptors(name: str, words_to_strip=_DESCRIPTOR_WORDS) -> str:
    """`name` without the descriptor words that trail it, keeping one word at least."""
    words = name.split()
    while len(words) > 1:
        if len(words) > 2 and tuple(words[-2:]) in _DESCRIPTOR_PHRASES:
            del words[-2:]
        elif words[-1] in words_to_strip:
            words.pop()
        else:
            break
    return " ".join(words)


def _strip_service_words(name: str) -> str:
    return _strip_descriptors(name, _SERVICE_WORDS)


def normalize_product_name(name: str) -> str:
    """Normalize a product name for lookup.

    A name that is not a known product is retried without its descriptor words
    and without a leading vendor word, so nmap's "Exim smtpd", "PostgreSQL DB"
    and "ISC BIND" reach the exact CPE query; the keyword search finds almost
    nothing for them. The shorter name is used only when it is a CPE_MAPPINGS
    product, and a dropped word only when it is that product's CPE vendor
    ("Mongo Express" is not Express).
    """
    name = _product_alias(name)
    if name in CPE_MAPPINGS:
        return name
    core = _product_alias(_strip_descriptors(name))
    if core in CPE_MAPPINGS:
        return core
    vendor, _, rest = core.partition(" ")
    rest = _product_alias(rest)
    if rest in CPE_MAPPINGS and CPE_MAPPINGS[rest][0] == vendor:
        return rest
    return name


def _product_alias(name: str) -> str:
    """The canonical spelling of a product name: "apache httpd" -> "apache"."""
    name = name.lower().strip()
    aliases = {
        # Apache variants
        "apache httpd": "apache", "apache http server": "apache",
        "apache2": "apache", "httpd": "apache",
        "apache-coyote": "tomcat", "apache coyote": "tomcat",
        "apache tomcat": "tomcat",
        "apache couchdb": "couchdb", "apache kafka": "kafka",
        "apache zookeeper": "zookeeper",
        "apache struts": "struts", "apache solr": "solr",
        # Microsoft
        "microsoft-iis": "iis", "microsoft iis": "iis",
        "microsoft-httpapi": "iis",
        # Node/JS
        "node": "node.js", "nodejs": "node.js",
        "nextjs": "next.js",
        "nuxtjs": "nuxt.js", "nuxt": "nuxt.js",
        "expressjs": "express", "node.js express": "express",
        "ruby on rails": "rails", "rubyonrails": "rails",
        # Databases
        "postgres": "postgresql", "mongo": "mongodb",
        # CMS
        "wp": "wordpress",
        "concrete5": "concrete cms",
        "aem": "adobe experience manager",
        "dotnetnuke": "dnn",
        "adobe coldfusion": "coldfusion",
        # Atlassian (Wappalyzer outputs "Atlassian Jira", etc.)
        "atlassian jira": "jira",
        "atlassian confluence": "confluence",
        "atlassian bitbucket": "bitbucket",
        # JS libraries
        "moment": "moment.js", "momentjs": "moment.js",
        "ember": "ember.js", "emberjs": "ember.js",
        "backbone": "backbone.js", "backbonejs": "backbone.js",
        "handlebarsjs": "handlebars",
        "dojo toolkit": "dojo",
        "prototype.js": "prototype",
        # E-commerce
        "zencart": "zen cart",
        # Webmail / Network
        "zimbra collaboration suite": "zimbra",
        "big-ip": "f5 big-ip",
        "pulse connect secure": "pulse secure",
        # Hosting
        "cpanel whm": "cpanel",
        # Servers
        "open resty": "openresty",
        # Community
        "mattermost server": "mattermost",
        # SSH/FTP
        "ssh": "openssh", "pure-ftpd": "pureftpd",
        # Proxies
        "squid-cache": "squid",
        "varnish cache": "varnish",
        # Multi-word server names
        "phusion passenger": "passenger",
        "eclipse jetty": "jetty",
    }
    return aliases.get(name, name)


def classify_cvss_score(score: float) -> str:
    """Classify CVSS score into severity level."""
    if score is None:
        return "unknown"
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score >= 0.1:
        return "LOW"
    return "NONE"


# =============================================================================
# NVD API Lookup
# =============================================================================

def _nvd_breaker():
    from recon.helpers import circuit_breaker as cb
    return cb.get_breaker("nvd", label="CVE-NVD")


def _vulners_breaker():
    from recon.helpers import circuit_breaker as cb
    return cb.get_breaker("vulners", label="CVE-Vulners")


def _nvd_classify(sent):
    """NVD signals a rate limit with 403 as well as 429, and refuses an unknown
    key with a 404 whose empty body puts the reason in the `message` header.
    Any other 404 is an unknown CPE: an answer, not a failure."""
    from recon.helpers import circuit_breaker as cb
    resp, keyed = sent
    status = cb.status_of(resp)
    if status in (403, 429):
        return cb.CallResult(None, cb.Outcome.RATE_LIMIT, f"HTTP {status}",
                             cb.retry_after_seconds(resp, default=6.0))
    if status == 404:
        try:
            reason = str((resp.headers or {}).get("message") or "").lower()
        except Exception:  # noqa: BLE001
            reason = ""
        if keyed and ("apikey" in reason or "api key" in reason):
            return cb.CallResult(None, cb.Outcome.FATAL, "404 key rejected")
        return cb.CallResult(None, cb.Outcome.NO_DATA, "HTTP 404")
    return cb.json_result(resp, keyed=keyed)


_CPE_VERSION_BOUNDS = (
    ("versionStartIncluding", operator.ge),
    ("versionStartExcluding", operator.gt),
    ("versionEndIncluding", operator.le),
    ("versionEndExcluding", operator.lt),
)


def _cpe_token(value: str) -> str:
    """A name as a CPE spells it: lowercase, "_" between words, no "\\" escapes."""
    return re.sub(r"[\s_-]+", "_", value.replace("\\", "").strip().lower())


def _version_tuple(version: Optional[str]) -> Optional[Tuple[int, ...]]:
    semver = _extract_semver(version or "")
    return tuple(int(part) for part in semver.split(".")) if semver else None


def _padded(a: Tuple[int, ...], b: Tuple[int, ...]):
    width = max(len(a), len(b))
    return a + (0,) * (width - len(a)), b + (0,) * (width - len(b))


def _loose_key(token: str) -> str:
    """A name without punctuation or a trailing "js": "angular.js" and "angularjs" agree."""
    return re.sub(r"js$", "", re.sub(r"[^a-z0-9]", "", token))


#: Qualifiers that make a vendor's product a separate one, not an edition of
#: the product named after it: elementor_pro is not Elementor, zabbix-agent2
#: not the Zabbix frontend.
_COMPANION_WORDS = frozenset({"pro", "premium", "enterprise", "desktop", "mobile", "android",
                              "ios", "client", "agent", "app", "plugin", "extension", "addon",
                              "addons", "theme", "sdk", "connector"})


def _in_line_of(token: str, name: str) -> bool:
    """Whether `token` is `name` or an edition of it ("liferay_portal", "datatables.net")."""
    if token == name:
        return True
    if not token.startswith((f"{name}_", f"{name}.")):
        return False
    qualifier = token[len(name) + 1:].split("_")
    return not any(re.sub(r"\d+$", "", word) in _COMPANION_WORDS for word in qualifier)


def _names_cpe_product(name: str, vendor: str, cpe_product: str) -> bool:
    """Whether the product a CPE names is `name` (both _cpe_tokens).

    It is the CPE product alone or after its vendor; the same name spelled
    with or without ".js" when the vendor is named after it too
    (angularjs:angular.js); or a product of the vendor named after `name`
    (liferay:liferay_portal, dropbear_ssh_project:dropbear_ssh). A product
    that only contains the name is not: "http" is not ibm:http_server,
    "font awesome" not newnine:font_awesome_4_menus.
    """
    key = _loose_key(name)
    return (name in (cpe_product, f"{vendor}_{cpe_product}")
            or bool(key) and key == _loose_key(cpe_product) == _loose_key(vendor)
            or _in_line_of(vendor, name) and _in_line_of(cpe_product, name))


def _cpe_match_covers(match: dict, names: set, version: Optional[str]) -> bool:
    """Whether one cpeMatch entry names the product (`names`, _cpe_tokens) at `version`."""
    parts = re.split(r"(?<!\\):", match.get("criteria") or "")
    if len(parts) < 6:
        return False
    vendor, cpe_product, cpe_version = _cpe_token(parts[3]), _cpe_token(parts[4]), parts[5]
    if not any(_names_cpe_product(name, vendor, cpe_product) for name in names):
        return False
    ours = _version_tuple(version)
    if ours is None:
        return True
    if cpe_version not in ("*", "-"):
        theirs = _version_tuple(cpe_version)
        # Either side may stop early: a fingerprint says "5.2" or drops the
        # "rc21" NVD pins as "0.94.14.21". Agreeing on what both state is a match.
        return theirs is not None and ours[:len(theirs)] == theirs[:len(ours)]
    for field, within in _CPE_VERSION_BOUNDS:
        bound = _version_tuple(match.get(field))
        # A bound that is not a number cannot place the version; the product matched.
        if bound is not None and not within(*_padded(ours, bound)):
            return False
    return True


def _text_names_version(cve_data: dict, names: set, version: Optional[str]) -> bool:
    """Whether the CVE's text names the product directly followed by `version`.

    "ACME mini_httpd 1.30 and prior" counts. Text that only carries the name
    inside another product does not: "Enable jQuery Migrate Helper plugin ...
    up to 1.4.1", "Slider Path for Elementor: from n/a through 3.0.0".
    """
    if not version:
        return False
    text = " ".join(d.get("value") or "" for d in cve_data.get("descriptions") or []
                    if d.get("lang") == "en")
    for name in names:
        words = r"[\s_-]+".join(re.escape(w) for w in name.split("_") if w)
        if re.search(rf"(?<![\w.-]){words}[\s_-]+v?{re.escape(version)}(?![\w.])",
                     text, re.IGNORECASE):
            return True
    return False


def _cve_affects(cve_data: dict, product: str, version: Optional[str],
                 cpe_hint: Optional[str] = None) -> bool:
    """Whether the CVE is about `product` (or nmap's CPE product for it) at
    `version`, by its NVD configuration.

    A keyword search only proves the words occur somewhere in the text: "http 3"
    returned InterScan VirusWall 3.6 and WinVNC 3.3.3, both for a "long HTTP GET
    request". A CVE NVD has not analysed has no configuration (many are
    "Deferred" and never will have one); its text must then name the product at
    this version.
    """
    names = {_cpe_token(product), _cpe_token(_strip_descriptors(product))}
    if cpe_hint:
        names.add(_cpe_token(cpe_hint))
    configurations = cve_data.get("configurations")
    if not configurations:
        return _text_names_version(cve_data, names, version)
    return any(
        match.get("vulnerable") and _cpe_match_covers(match, names, version)
        for config in configurations
        for node in config.get("nodes") or []
        for match in node.get("cpeMatch") or []
    )


#: The most NVD returns per request, and the most pages read for one search.
NVD_PAGE_SIZE = 2000
NVD_MAX_PAGES = 2


def _nmap_cpe_product(cpe) -> Optional[str]:
    """The application product of an nmap CPE: "cpe:/a:webmin:webmin:1.890" -> "webmin"."""
    if not isinstance(cpe, str):
        return None
    parts = cpe.strip().lower().split(":")
    if parts[:2] == ["cpe", "/a"] and len(parts) > 3:
        return parts[3] or None
    if parts[:3] == ["cpe", "2.3", "a"] and len(parts) > 4:
        return parts[4] or None
    return None


def _nvd_pacing(keys) -> float:
    """Seconds between NVD requests: 5 per 30s are allowed without a key, 50 with one."""
    return 0.6 if keys.has_key else 6.0


def _nvd_fetch(params: dict, keys, *, admitted: bool):
    """Every record NVD answers for `params`, through the `nvd` breaker.

    NVD lists the oldest CVEs first, so reading only the first `max_results`
    would keep the oldest and miss the newest, often the most severe (Exim
    4.92: 48 CVEs, two 9.8s past the first 20). Returns a CallResult whose data
    is the list of NVD vulnerability records.
    """
    from recon.helpers import circuit_breaker as cb
    records, start, res = [], 0, None
    for page in range(NVD_MAX_PAGES):
        if page:
            time.sleep(_nvd_pacing(keys))
        page_params = {**params, "resultsPerPage": NVD_PAGE_SIZE, "startIndex": start}

        def send(key, page_params=page_params):
            headers = {"apiKey": key} if key else {}
            return (requests.get(NVD_API_URL, params=page_params, headers=headers, timeout=60),
                    bool(key))

        res = cb.guarded_call(_nvd_breaker(), send, _nvd_classify, keys=keys,
                              admitted=admitted and not page)
        if not res.ok:
            break
        body = res.data or {}
        batch = body.get("vulnerabilities") or []
        records += batch
        start += len(batch)
        if not batch or start >= (body.get("totalResults") or 0):
            break
    if records:
        return cb.CallResult(records, cb.Outcome.OK, res.detail)
    return cb.CallResult([], res.outcome, res.detail)


def _nvd_cve(cve_data: dict) -> dict:
    """The CVE dict the pipeline stores, from one NVD record."""
    cve_id = cve_data.get("id", "")
    metrics = cve_data.get("metrics", {})
    cvss_score = severity = None
    # A CVE scored in 2016-2019 often has only a v3.0 metric, and an unscored
    # CVE sorts below every scored one.
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV40", "cvssMetricV2"):
        if metrics.get(key):
            metric = metrics[key][0]
            cvss_score = metric.get("cvssData", {}).get("baseScore")
            severity = (metric.get("baseSeverity") if key == "cvssMetricV2"
                        else metric.get("cvssData", {}).get("baseSeverity"))
            break

    descriptions = cve_data.get("descriptions", [])
    description = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")

    refs = cve_data.get("references", [])
    reference_urls = [ref.get("url") for ref in refs[:3] if ref.get("url")]

    return {
        "id": cve_id,
        "cvss": cvss_score,
        "severity": severity,
        "description": description[:300] if description else "",
        "published": cve_data.get("published"),
        "references": reference_urls,
        "source": "nvd",
        "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
    }


def _nvd_query(product: str, version: str, max_results: int, keys, *,
               admitted: bool = False, cpe_hint: Optional[str] = None):
    """One technology's NVD lookup through the `nvd` breaker. Returns a CallResult
    whose data is the `max_results` CVE dicts with the highest CVSS.

    A CPE_MAPPINGS product is asked by its exact CPE name, which NVD matches
    itself. Any other product is asked by its name alone, since a CVE's text
    gives its range ("before 1.13.0") rather than the version found, and each
    hit is kept only when _cve_affects places it at this version. `cpe_hint` is
    the CPE product nmap reported for the service: NVD also matches it, under
    any vendor, against every CVE's configuration, which finds the CVEs whose
    text never names the product (Webmin for nmap's "MiniServ", Zerologon for
    Samba).
    """
    from recon.helpers import circuit_breaker as cb
    product_normalized = normalize_product_name(product)
    cpe_info = CPE_MAPPINGS.get(product_normalized)

    # Each search, and whether NVD placed the version itself (a CPE match) or
    # only the name occurs in the CVE's text (a keyword search).
    if cpe_info:
        vendor, cpe_product = cpe_info
        searches = [({"cpeName": f"cpe:2.3:a:{vendor}:{cpe_product}:{version or '*'}"
                                 ":*:*:*:*:*:*:*"}, True)]
    else:
        cpe_product = cpe_hint
        searches = []
        if cpe_hint and version:
            searches.append(({"virtualMatchString": f"cpe:2.3:a:*:{cpe_hint}:{version}"}, True))
        searches.append(({"keywordSearch": _strip_service_words(product_normalized)}, False))

    found, results = {}, []
    for i, (params, nvd_placed_version) in enumerate(searches):
        if i:
            time.sleep(_nvd_pacing(keys))
        res = _nvd_fetch(params, keys, admitted=admitted and not i)
        results.append(res)
        for vuln in res.data or []:
            cve_data = vuln.get("cve", {})
            if nvd_placed_version:
                # A CPE match also returns the CVEs of what runs ON the product,
                # listed beside it as not vulnerable: a WordPress plugin's under
                # WordPress, a TYPO3 extension's under TYPO3.
                keep = (not cve_data.get("configurations")
                        or _cve_affects(cve_data, product_normalized, None, cpe_product))
            else:
                keep = _cve_affects(cve_data, product_normalized, version, cpe_product)
            if keep:
                found.setdefault(cve_data.get("id", ""), _nvd_cve(cve_data))

    if not any(r.answered for r in results):
        return cb.CallResult([], results[-1].outcome, results[-1].detail)
    cves = sorted(found.values(), key=lambda c: c.get("cvss") or 0, reverse=True)[:max_results]
    return cb.CallResult(cves, cb.Outcome.OK if cves else cb.Outcome.NO_DATA, results[-1].detail)


def lookup_cves_nvd(
    product: str,
    version: str = None,
    max_results: int = 20,
    api_key: str = None,
    key_rotator=None,
) -> List[Dict]:
    """
    Query NVD API for CVEs affecting a product/version.
    
    Args:
        product: Product name (e.g., 'nginx')
        version: Version string (e.g., '1.19.0')
        max_results: Maximum results to return
        api_key: Optional NVD API key for higher rate limits
        
    Returns:
        List of CVE dictionaries
    """
    from recon.helpers import circuit_breaker as cb
    keys = cb.KeyPool(key_rotator, api_key or "", label="CVE-NVD")
    return _nvd_query(product, version, max_results, keys).data


# =============================================================================
# Vulners API Lookup
# =============================================================================

def _vulners_classify(resp):
    """Vulners answers in-body: "OK" (results), "warning" (nothing found),
    "error" (a refused key among others). The body is read only to classify."""
    from recon.helpers import circuit_breaker as cb
    res = cb.json_result(resp, keyed=True)
    if not res.ok:
        return res
    data = res.data if isinstance(res.data, dict) else {}
    result = str(data.get("result") or "").lower()
    if result == "ok":
        return cb.CallResult(data, cb.Outcome.OK, res.detail)
    if result == "warning":
        return cb.CallResult(data, cb.Outcome.NO_DATA, "nothing found")
    inner = data.get("data") if isinstance(data.get("data"), dict) else {}
    message = f"{inner.get('error') or ''} {inner.get('errorCode') or ''}".lower()
    if "key" in message or "auth" in message or "credential" in message:
        return cb.CallResult(None, cb.Outcome.FATAL, "key rejected")
    if "limit" in message or "too many" in message:
        return cb.CallResult(None, cb.Outcome.RATE_LIMIT, "rate limited")
    return cb.CallResult(None, cb.Outcome.TRANSIENT, "Vulners error body")


def _vulners_query(product: str, version: str, keys, *, admitted: bool = False):
    """One Vulners lookup through the `vulners` breaker. Returns a CallResult
    whose data is the list of CVE dicts."""
    from recon.helpers import circuit_breaker as cb
    if not version:
        return cb.CallResult([], cb.Outcome.NO_DATA, "no version")

    def send(key):
        params = {"software": f"{product} {version}", "version": version, "type": "software"}
        # Vulners accepts the key only in the X-Api-Key header since 2025-10-02. A
        # key in the query string gets the same 403 Cloudflare challenge as no key,
        # and it would land in URLs and logs.
        headers = {"X-Api-Key": key} if key else {}
        return requests.get(VULNERS_API_URL, params=params, headers=headers, timeout=30)

    res = cb.guarded_call(_vulners_breaker(), send, _vulners_classify, keys=keys,
                          admitted=admitted)
    if not res.ok:
        return cb.CallResult([], res.outcome, res.detail)
    cves = []
    for vuln in (res.data.get("data") or {}).get("search", []):
        vuln_id = vuln.get("id", "")
        cvss_data = vuln.get("cvss", {})

        cves.append({
            "id": vuln_id,
            "cvss": cvss_data.get("score"),
            "severity": classify_cvss_score(cvss_data.get("score")),
            "description": vuln.get("description", "")[:300],
            "published": vuln.get("published"),
            "references": [vuln.get("href")] if vuln.get("href") else [],
            "source": "vulners",
            "url": f"https://vulners.com/{vuln.get('type', 'cve')}/{vuln_id}",
        })
    return cb.CallResult(cves, cb.Outcome.OK if cves else cb.Outcome.NO_DATA, res.detail)


def lookup_cves_vulners(product: str, version: str, api_key: str = None, key_rotator=None) -> List[Dict]:
    """
    Query Vulners API for CVEs (like Nmap's vulners script).

    Args:
        product: Product name
        version: Version string (required for Vulners)
        api_key: Vulners API key
        key_rotator: Optional KeyRotator for key rotation

    Returns:
        List of CVE dictionaries
    """
    from recon.helpers import circuit_breaker as cb
    keys = cb.KeyPool(key_rotator, api_key or "", label="CVE-Vulners")
    return _vulners_query(product, version, keys).data


# =============================================================================
# Main CVE Lookup Orchestration
# =============================================================================

def run_cve_lookup(
    recon_data: dict,
    enabled: bool = True,
    source: str = "nvd",
    max_cves: int = 20,
    min_cvss: float = 0.0,
    vulners_api_key: str = None,
    nvd_api_key: str = None,
    nvd_key_rotator=None,
    vulners_key_rotator=None,
) -> Dict:
    """
    Lookup CVEs for all technologies detected by httpx.
    
    Args:
        recon_data: Reconnaissance data containing httpx results
        enabled: Whether CVE lookup is enabled
        source: API source ('nvd' or 'vulners')
        max_cves: Maximum CVEs per technology
        min_cvss: Minimum CVSS score to include
        vulners_api_key: Vulners API key
        nvd_api_key: NVD API key
        
    Returns:
        Dictionary to add to recon_data
    """
    if not enabled:
        return {}
    
    print(f"\n{'='*60}")
    print("[*][CVE] Technology-Based Vulnerability Discovery")
    print(f"{'='*60}")
    print(f"[*][CVE] Source: {source.upper()}")
    print(f"[*][CVE] Min CVSS: {min_cvss}")
    
    # Raw detector string -> (name, version), each parsed in its own source's
    # format: httpx labels are "Name:version", the others "Name/version".
    technologies = {}
    # Raw detector string -> the CPE product nmap reported for that service.
    cpe_hints = {}
    httpx_data = recon_data.get("http_probe", {})

    for url_data in httpx_data.get("by_url", {}).values():
        for tech in url_data.get("technologies", []):
            technologies.setdefault(tech, parse_httpx_technology(tech))
        server = url_data.get("server")
        if server:
            # Split compound server headers like
            # "Apache/2.4.49 (Unix) OpenSSL/1.1.1l PHP/8.1.2"
            # into individual product strings
            for product in split_server_header(server):
                technologies.setdefault(product, parse_technology_string(product))

    # Also extract technologies from banner grab (non-HTTP services like SSH, FTP, MySQL)
    banner_data = recon_data.get("banner_grab", {})
    for service_type, instances in banner_data.get("services_found", {}).items():
        for instance in instances:
            version_str = instance.get("version")
            if version_str:
                technologies.setdefault(version_str, parse_technology_string(version_str))

    # Also extract technologies from Nmap service version detection
    nmap_data = recon_data.get("nmap_scan", {})
    for svc in nmap_data.get("services_detected", []):
        product = svc.get("product", "")
        version = svc.get("version", "")
        if product and version:
            tech = f"{product}/{version}"
            technologies.setdefault(tech, parse_technology_string(tech))
            cpe_hints[tech] = cpe_hints.get(tech) or _nmap_cpe_product(svc.get("cpe"))

    # Filter and deduplicate technologies to lookup
    lookups = {}
    skip_list = ["ubuntu", "debian", "centos", "linux", "windows",
                 "dreamweaver", "frontpage", "html", "css", "aws",
                 "cloudflare", "google analytics", "google tag manager",
                 "facebook pixel", "hotjar", "google font api"]

    for tech, (name, version) in technologies.items():
        name = normalize_product_name(name)
        if not version or name in skip_list:
            continue
        entry = lookups.setdefault((name.lower(), version.lower()), [tech, name, version, None])
        # The Server header and nmap often report one product ("MiniServ/1.890");
        # the lookup keeps the first string and nmap's CPE for it.
        entry[3] = entry[3] or cpe_hints.get(tech)
    tech_to_lookup = list(lookups.values())
    
    print(f"\n[*][CVE] Technologies with versions: {len(tech_to_lookup)}")
    
    if not tech_to_lookup:
        print("[!][CVE] No technologies with versions found")
        return {"technology_cves": {"summary": {"total_cves": 0}}}
    
    # Lookup CVEs
    cve_results = {}
    all_cves = []
    from recon.helpers import circuit_breaker as cb
    use_vulners = source == "vulners" and bool(vulners_api_key)
    keys = (cb.KeyPool(vulners_key_rotator, vulners_api_key or "", label="CVE-Vulners") if use_vulners
            else cb.KeyPool(nvd_key_rotator, nvd_api_key or "", label="CVE-NVD"))
    breaker = _vulners_breaker() if use_vulners else _nvd_breaker()
    cve_scope = cb.scope(("nvd", "vulners"), label="CVE", unit="technolog(ies)")
    nvd_pacing = _nvd_pacing(keys)
    hinted = False

    for i, (tech, name, version, cpe_hint) in enumerate(tech_to_lookup, 1):
        # A paused or stopped source is skipped silently; the scope summarises it.
        if not breaker.allow():
            continue
        print(f"[*][CVE] [{i}/{len(tech_to_lookup)}] {tech}...", end=" ", flush=True)

        if use_vulners:
            res = _vulners_query(name, version, keys, admitted=True)
        else:
            res = _nvd_query(name, version, max_cves, keys, admitted=True, cpe_hint=cpe_hint)
        cves = res.data or []
        if not res.answered:
            print(f"failed ({res.detail})")
            if (res.outcome is cb.Outcome.RATE_LIMIT and not use_vulners
                    and not keys.has_key and not hinted):
                hinted = True
                print("[!][CVE] NVD API rate limited. Configure NVD API Key in Global Settings "
                      "→ Tool API Keys for higher limits.")
            continue
        
        # Filter by min CVSS
        if min_cvss > 0:
            cves = [c for c in cves if (c.get("cvss") or 0) >= min_cvss]
        
        cves.sort(key=lambda x: x.get("cvss") or 0, reverse=True)
        cves = cves[:max_cves]
        
        if cves:
            cve_results[tech] = {
                "technology": tech,
                "product": name,
                "version": version,
                "cve_count": len(cves),
                "critical": len([c for c in cves if c.get("severity") == "CRITICAL"]),
                "high": len([c for c in cves if c.get("severity") == "HIGH"]),
                "cves": cves,
            }
            all_cves.extend(cves)
            print(f"✓ {len(cves)} CVEs found")
        else:
            print("no CVEs")
        
        # NVD pacing, after an answer only: a failure has already cost its
        # time, and a rate limit is paced by the breaker's shared pause.
        if not use_vulners and i < len(tech_to_lookup):
            time.sleep(nvd_pacing)

    cve_scope.finish("cve_lookup")
    
    # Count unique CVEs
    unique_cve_ids = set()
    for tech_data in cve_results.values():
        for cve in tech_data.get("cves", []):
            unique_cve_ids.add(cve["id"])

    # Count severity distribution
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for tech_data in cve_results.values():
        for cve in tech_data.get("cves", []):
            # An unscored CVE carries severity None, not a missing key.
            sev = (cve.get("severity") or "").upper()
            if sev in severity_counts:
                severity_counts[sev] += 1

    # Build result
    result = {
        "technology_cves": {
            "lookup_timestamp": datetime.now().isoformat(),
            "source": source,
            "technologies_checked": len(tech_to_lookup),
            "technologies_with_cves": len(cve_results),
            "by_technology": cve_results,
            "summary": {
                "total_unique_cves": len(unique_cve_ids),
                "critical": severity_counts["CRITICAL"],
                "high": severity_counts["HIGH"],
                "medium": severity_counts["MEDIUM"],
                "low": severity_counts["LOW"],
            }
        }
    }
    
    # Print summary
    summary = result["technology_cves"]["summary"]
    print(f"\n[+][CVE] CVE LOOKUP SUMMARY:")
    print(f"[+][CVE] Total unique CVEs: {summary['total_unique_cves']}")
    if summary['critical'] > 0:
        print(f"[!][CVE] CRITICAL: {summary['critical']}")
    if summary['high'] > 0:
        print(f"[!][CVE] HIGH: {summary['high']}")
    if summary['medium'] > 0:
        print(f"[*][CVE] MEDIUM: {summary['medium']}")
    print(f"{'='*60}")
    
    return result

