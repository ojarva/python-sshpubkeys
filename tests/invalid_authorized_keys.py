from sshpubkeys.exceptions import InvalidKeyError, MalformedDataError

from .valid_keys import keys as valid_keys

from.invalid_keys import keys as invalid_keys

items = [
    ["lines_with_spaces", " # Comments\n  \n" + valid_keys[0][0] + "\nasdf", InvalidKeyError],
    ["invalid_key", "# Comments\n" + invalid_keys[0][0], MalformedDataError],
]
