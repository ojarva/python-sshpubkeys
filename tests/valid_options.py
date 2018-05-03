options = [
    ["empty_options", "", {}],
    ["single_basic", "no-user-rc", {
        "no-user-rc": [True]
    }],
    [
        "single_quoted", 'from="*.sales.example.net,!pc.sales.example.net"', {
            'from': ['*.sales.example.net,!pc.sales.example.net']
        }
    ],
    ["equals_in_quotes", 'environment="NAME=value"', {
        'environment': ['NAME=value']
    }],
    [
        "multiple_quoted", 'environment="NAME=value",from="*.sales.example.net"', {
            'environment': ['NAME=value'],
            'from': ['*.sales.example.net']
        }
    ],
    [
        "multiple_options_combined", 'permitopen="host:port",port-forwarding,no-port-forwarding', {
            'no-port-forwarding': [True],
            'port-forwarding': [True],
            'permitopen': ['host:port']
        }
    ],
]
