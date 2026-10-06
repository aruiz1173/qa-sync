class QASyncError(Exception):
    """Error esperado que puede mostrarse de forma segura en la interfaz."""


class ConfigurationError(QASyncError):
    pass


class ExternalServiceError(QASyncError):
    pass


class UsageLimitError(ExternalServiceError):
    """El proveedor respondió que la cuenta alcanzó su límite de uso."""


class ValidationError(QASyncError):
    pass


class ConflictError(QASyncError):
    """A local proposal was changed by another editor since it was opened."""
