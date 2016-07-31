class InvalidKeyException(Exception):
    """ Key is invalid. """
    pass


class InvalidKeyLengthException(InvalidKeyException):
    """ Invalid key length """
    pass


class TooShortKeyException(InvalidKeyLengthException):
    """ Key is shorter than what specification allows """
    pass


class TooLongKeyException(InvalidKeyLengthException):
    """ Key is longer than what specification allows """
    pass


class InvalidTypeException(InvalidKeyException):
    """ Key type is invalid """
    pass


class MalformedDataException(InvalidKeyException):
    """ Key is invalid - unable to read the data """
    pass


class InvalidOptionsException(MalformedDataException):
    """ Options string is invalid """
    pass


class InvalidOptionNameException(InvalidOptionsException):
    """ Invalid option name (contains disallowed characters) """
    pass


class UnknownOptionNameException(InvalidOptionsException):
    """ Option name is unknown. """
    pass


class MissingMandatoryOptionValueException(InvalidOptionsException):
    """ Option must have value, but value is missing. """
    pass
