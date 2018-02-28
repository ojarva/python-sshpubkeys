# pylint:disable=line-too-long,too-many-ancestors

"""Exceptions for sshpubkeys."""


class InvalidKeyException(Exception):
    """Invalid key - something is wrong with the key, and it should not be accepted, as OpenSSH will not work with it."""
    pass


class InvalidKeyError(InvalidKeyException):
    """Invalid key - something is wrong with the key, and it should not be accepted, as OpenSSH will not work with it."""
    pass


class InvalidKeyLengthException(InvalidKeyError):
    """Invalid key length - either too short or too long.

    See also TooShortKeyException and TooLongKeyException."""
    pass


class InvalidKeyLengthError(InvalidKeyError):
    """Invalid key length - either too short or too long.

    See also TooShortKeyException and TooLongKeyException."""
    pass


class TooShortKeyException(InvalidKeyLengthError):
    """Key is shorter than what the specification allow."""
    pass


class TooShortKeyError(TooShortKeyException):
    """Key is shorter than what the specification allows."""
    pass


class TooLongKeyException(InvalidKeyLengthError):
    """Key is longer than what the specification allows."""
    pass


class TooLongKeyError(TooLongKeyException):
    """Key is longer than what the specification allows."""
    pass


class InvalidTypeException(InvalidKeyError):
    """Key type is invalid or unrecognized."""
    pass


class InvalidTypeError(InvalidTypeException):
    """Key type is invalid or unrecognized."""
    pass


class MalformedDataException(InvalidKeyError):
    """The key is invalid - unable to parse the data. The data may be corrupted, truncated, or includes extra content that is not allowed."""
    pass


class MalformedDataError(MalformedDataException):
    """The key is invalid - unable to parse the data. The data may be corrupted, truncated, or includes extra content that is not allowed."""
    pass


class InvalidOptionsException(MalformedDataError):
    """Options string is invalid: it contains invalid characters, unrecognized options, or is otherwise malformed."""
    pass


class InvalidOptionsError(InvalidOptionsException):
    """Options string is invalid: it contains invalid characters, unrecognized options, or is otherwise malformed."""
    pass


class InvalidOptionNameException(InvalidOptionsError):
    """Invalid option name (contains disallowed characters, or is unrecognized.)."""
    pass


class InvalidOptionNameError(InvalidOptionNameException):
    """Invalid option name (contains disallowed characters, or is unrecognized.)."""
    pass


class UnknownOptionNameException(InvalidOptionsError):
    """Unrecognized option name."""
    pass


class UnknownOptionNameError(UnknownOptionNameException):
    """Unrecognized option name."""
    pass


class MissingMandatoryOptionValueException(InvalidOptionsError):
    """Mandatory option value is missing."""
    pass


class MissingMandatoryOptionValueError(MissingMandatoryOptionValueException):
    """Mandatory option value is missing."""
    pass
