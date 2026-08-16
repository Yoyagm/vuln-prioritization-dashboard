"""Short names for the weakness classes that actually show up in the catalogue.

The NVD carries only identifiers, and "CWE-787" tells a reader nothing. These
are MITRE's common names, shortened to fit an axis label; anything not listed
falls back to its bare identifier rather than guessing.
"""

from __future__ import annotations

NAMES: dict[str, str] = {
    "CWE-20": "Improper input validation",
    "CWE-22": "Path traversal",
    "CWE-77": "Command injection",
    "CWE-78": "OS command injection",
    "CWE-79": "Cross-site scripting",
    "CWE-89": "SQL injection",
    "CWE-94": "Code injection",
    "CWE-119": "Memory buffer overflow",
    "CWE-120": "Classic buffer overflow",
    "CWE-125": "Out-of-bounds read",
    "CWE-190": "Integer overflow",
    "CWE-269": "Improper privilege management",
    "CWE-284": "Improper access control",
    "CWE-287": "Improper authentication",
    "CWE-306": "Missing authentication",
    "CWE-352": "Cross-site request forgery",
    "CWE-362": "Race condition",
    "CWE-416": "Use after free",
    "CWE-434": "Unrestricted file upload",
    "CWE-502": "Deserialisation of untrusted data",
    "CWE-611": "XML external entity",
    "CWE-787": "Out-of-bounds write",
    "CWE-798": "Hard-coded credentials",
    "CWE-843": "Type confusion",
    "CWE-863": "Incorrect authorisation",
}


def label(cwe_id: str) -> str:
    """``CWE-787`` becomes ``Out-of-bounds write (CWE-787)``, or stays as-is."""
    name = NAMES.get(cwe_id)
    return f"{name} ({cwe_id})" if name else cwe_id
