# Custom exceptions for error handling

class EncryptionAppError(Exception):
    """Base exception for the app."""


class AlgorithmError(EncryptionAppError):
    """Algorithm-related errors."""


class KeyErrorApp(EncryptionAppError):
    """Key-related errors (name avoid clash with built-in KeyError)."""


class FileProcessingError(EncryptionAppError):
    """File-related errors."""
