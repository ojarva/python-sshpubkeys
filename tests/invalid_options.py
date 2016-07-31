from sshpubkeys.exceptions import InvalidOptionsException, UnknownOptionNameException, InvalidOptionNameException, MissingMandatoryOptionValueException
options = [
    ["includes_space", "no-user-rc ", InvalidOptionsException],
    ["includes_space_multiple", "no-user-rc, port-forwarding", InvalidOptionsException],
    ["includes_space_before_comma",
        "no-user-rc ,port-forwarding", InvalidOptionsException],
    ["empty_option_end", "no-user-rc,", InvalidOptionsException],
    ["empty_option_beginning", ",no-user-rc", InvalidOptionsException],
    ["empty_option_middle", "no-user-rc,,port-forwarding", InvalidOptionsException],
    ["unbalanced_quotes", 'from="asdf', InvalidOptionsException],
    ["invalid_characters_in_key_percent", 'from%', InvalidOptionNameException],
    ["invalid_characters_in_key_parenthesis", 'from)', InvalidOptionNameException],
    ["invalid_characters_in_key_space", 'fr om', InvalidOptionNameException],
    ["unknown_option_name", "random-option-name", UnknownOptionNameException],
    ["unbalanced_quotes_complex", 'from="asdf",no-user-rc"', InvalidOptionsException],
    ["parameter_missing", 'from,no-user-rc"',
        MissingMandatoryOptionValueException],
]
