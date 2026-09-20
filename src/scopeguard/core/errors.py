class ScopeGuardError(Exception):
    """Base error."""

class ScopeMissingError(ScopeGuardError):
    """No scope.yaml found."""

class ScopeExpiredError(ScopeGuardError):
    """Scope authorization has expired."""

class ScopeViolationError(ScopeGuardError):
    """Target is not listed in the authorized scope."""

class BackendUnavailableError(ScopeGuardError):
    """Required system tool is missing (e.g. iw)."""
