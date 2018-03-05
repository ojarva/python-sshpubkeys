from .valid_keys import keys

items = [
    ["empty_file", "", 0],
    ["single_key", keys[0][0], 1],
    ["comment_only", "# Nothing else than a comment here", 0],
    ["lines_with_spaces", " # Comments\n  \n" + keys[0][0] + "\n#asdf", 1],
]
