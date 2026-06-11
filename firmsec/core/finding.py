"""The Finding model — one security observation produced by an analyzer."""

from .constants import SEVERITY_ORDER


class Finding:
    def __init__(self, category, severity, path, detail,
                 line=None, evidence=None, confidence="Medium", auth_hint=None):
        self.category   = category
        self.severity   = severity
        self.path       = str(path)
        self.detail     = detail
        self.line       = line
        self.evidence   = evidence
        self.confidence = confidence  # "High" | "Medium" | "Low"
        self.auth_hint  = auth_hint   # "auth" | "unauth" | "unknown" | None

    def sort_key(self):
        return SEVERITY_ORDER.get(self.severity, 99)
