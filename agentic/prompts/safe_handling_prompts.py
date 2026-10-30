"""Handling rules the access_control and path_traversal skills carry on every project.

The RoE's data-handling line ("do NOT display any sensitive data") told the model
what not to do but never how to prove a finding without doing it, and with the
route exposure module off a live session printed an export's e-mails, a `.env`
password, a `.git` blob's token and a session cookie, and requested `/logout`
and `/account/reset` in the informational phase. These parts are the recipe.

Each skill gets its own constants, worded for what it reads and writes: the part
registry keys an override on one constant per part.
"""


def _values(carriers: str, pattern: str) -> str:
    return f"""
## KEEP VALUES OUT OF THIS CONVERSATION

A tool result reaches the model and stays in the session's transcript, so a secret or a
person's data that a tool prints is a copy the engagement did not agree to (the RoE's
data handling above). Prove with derived facts instead:

- A response that may carry secrets or personal data ({carriers}) goes to a kali file:
  execute_curl with `-s -o /tmp/<name>.body -w '%{{http_code}} %{{size_download}} %{{content_type}}'`.
- ONE execute_code script reads it and prints only derived facts: status, size, key
  names, counts, which pattern matched ({pattern}), and 8-character SHA-256 prefixes to
  compare two responses. Never a value, record, password, token or cookie. It deletes
  the file when done.
- A secret you must USE (a recovered password, an API key) stays in its file: the next
  request reads it from there (`-H @/tmp/<name>.hdr`, or execute_code), never from this
  conversation.
- Never print a credential header. With `use_session=true`, or any request carrying a
  Cookie, Authorization or API-key header, `-v`, `-i`, `--trace`, `-D -` and `-o -` are
  FORBIDDEN, and so is echoing a `Set-Cookie`.
- Evidence, chain findings and the final answer carry the same derived facts only.
"""


_READ_ONLY = """
## REQUESTS THAT CHANGE STATE

- In every phase, never request a route that ends or changes a session or an account,
  whatever its method: logout / signout, password or account reset, account deletion
  or deactivation, unsubscribe, cancel. One such request can log out the session you
  test with or change a real user's account. Before any discovery fuzz, filter those
  words out of the wordlist first:
  `grep -viE 'logout|sign-?out|reset|delete|remove|deactivate|unsubscribe|cancel'`.
- Informational phase: read-only. GET, HEAD and OPTIONS only."""


ACCESS_CONTROL_SAFE_VALUES = _values(
    "an export, a profile, another user's object, a token endpoint, a config file",
    "an `email` key present, 12 records, a `password_hash` field")

PATH_TRAVERSAL_SAFE_VALUES = _values(
    "a file read through the traversal, a config or `.env` file, a `.git` object, a backup",
    "`root:x:0:0` present, 7 `KEY=` lines, zip magic")

ACCESS_CONTROL_SAFE_STATE = _READ_ONLY + """
- Exploitation phase: a write (create, update, delete) targets an object you created
  with a test account, or one the engagement names as a test object; never another
  user's real account or data, and never a logout of the session you test with.
  Reading another user's object already proves an IDOR: changing it adds no proof.
"""

PATH_TRAVERSAL_SAFE_STATE = _READ_ONLY + """
- Exploitation phase: a write (an upload, an archive extraction, a log-poisoning
  request) uses a file name of your own and never overwrites or deletes an existing
  file; never a logout of the session you test with. Reading a file already proves the
  traversal: writing one is a separate step the skill's own rules gate.
"""
