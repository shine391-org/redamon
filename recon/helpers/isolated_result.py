"""The answer of an `_isolated` wrapper whose module writes more than its own key.

An `_isolated` wrapper runs its module on a deep copy of combined_result and
hands back the module's payload, which the fan-out stores under the tool's key.
A module that also writes a second top-level key (run_vuln_scan writes the CVE
lookup's `technology_cves` beside `vuln_scan`) would lose it with the copy, so
its wrapper answers with TopLevelKeys instead, and the fan-out merges each key.

The type is the declaration: a plain dict is always one payload, whatever keys
it holds, so no caller ever guesses from key names.
"""


class TopLevelKeys(dict):
    """Several top-level combined_result keys, by name, from one `_isolated` run."""
