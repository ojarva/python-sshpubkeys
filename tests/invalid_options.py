from sshpubkeys.exceptions import (
    InvalidOptionNameError, InvalidOptionsError, MissingMandatoryOptionValueError, UnknownOptionNameError
)

options = [
    ["includes_space", "no-user-rc ", InvalidOptionsError],
    ["includes_space_multiple", "no-user-rc, port-forwarding", InvalidOptionsError],
    ["includes_space_before_comma", "no-user-rc ,port-forwarding", InvalidOptionsError],
    ["empty_option_end", "no-user-rc,", InvalidOptionsError],
    ["empty_option_beginning", ",no-user-rc", InvalidOptionsError],
    ["empty_option_middle", "no-user-rc,,port-forwarding", InvalidOptionsError],
    ["unbalanced_quotes", 'from="asdf', InvalidOptionsError],
    ["invalid_characters_in_key_percent", 'from%', InvalidOptionNameError],
    ["invalid_characters_in_key_parenthesis", 'from)', InvalidOptionNameError],
    ["invalid_characters_in_key_space", 'fr om', InvalidOptionNameError],
    ["unknown_option_name", "random-option-name", UnknownOptionNameError],
    ["unbalanced_quotes_complex", 'from="asdf",no-user-rc"', InvalidOptionsError],
    ["parameter_missing", 'from,no-user-rc"', MissingMandatoryOptionValueError],
]
