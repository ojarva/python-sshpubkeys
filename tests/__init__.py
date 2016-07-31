""" Creates tests from lists of both valid and invalid keys.

New test is generated for each key so that running unittests gives out meaningful errors.

"""

import unittest
from sshpubkeys import *
from .valid_keys import keys as list_of_valid_keys
from .valid_keys_rfc4716 import keys as list_of_valid_keys_rfc4716
from .invalid_keys import keys as list_of_invalid_keys
from .valid_options import options as list_of_valid_options
from .invalid_options import options as list_of_invalid_options


class TestMisc(unittest.TestCase):

    def test_none_to_constructor(self):
        ssh = SSHKey(None)
        self.assertIsNone(ssh.keydata)
        self.assertRaises(ValueError, ssh.parse)


class TestKeys(unittest.TestCase):

    def check_key(self, pubkey, bits, fingerprint_md5, fingerprint_sha256, options, comment, **kwargs):
        """ Checks valid key """
        ssh = SSHKey(pubkey, **kwargs)
        ssh.parse()
        self.assertEqual(ssh.bits, bits)
        self.assertEqual(ssh.hash_md5(), fingerprint_md5)
        self.assertEqual(ssh.options_raw, options)
        self.assertEqual(ssh.comment, comment)
        if fingerprint_sha256 is not None:
            self.assertEqual(ssh.hash_sha256(), fingerprint_sha256)

    def check_fail(self, pubkey, expected_error, **kwargs):
        """ Checks that key check raises specified exception """
        # Don't use with statement here - it does not work with Python 2.6 unittest module
        ssh_key = SSHKey(pubkey, **kwargs)
        self.assertRaises(expected_error, ssh_key.parse)


class TestOptions(unittest.TestCase):

    def check_valid_option(self, option, parsed_option):
        ssh = SSHKey()
        parsed = ssh.parse_options(option)
        self.assertEqual(parsed, parsed_option)

    def check_invalid_option(self, option, expected_error):
        ssh = SSHKey()
        self.assertRaises(expected_error, ssh.parse_options, option)


def loop_options(options):
    """ Loop over list of options and dynamically create tests """
    def ch(option, parsed_option):
        return lambda self: self.check_valid_option(option, parsed_option)
    for i, items in enumerate(options):
        prefix_tmp = "%s_%s" % (items[0], i)
        setattr(TestOptions, "test_%s" % prefix_tmp, ch(items[1], items[2]))


def loop_invalid_options(options):
    def ch(option, expected_error):
        return lambda self: self.check_invalid_option(option, expected_error)
    for i, items in enumerate(options):
        prefix_tmp = "%s_%s" % (items[0], i)
        setattr(TestOptions, "test_%s" % prefix_tmp, ch(items[1], items[2]))


def loop_valid(keyset, prefix):
    """ Loop over list of valid keys and dynamically create tests """
    def ch(pubkey, bits, fingerprint_md5, fingerprint_sha256, options, comment, **kwargs):
        return lambda self: self.check_key(pubkey, bits, fingerprint_md5, fingerprint_sha256, options, comment, **kwargs)
    for i, items in enumerate(keyset):
        modes = items.pop()
        prefix_tmp = "%s_%s" % (prefix, items.pop())
        for mode in modes:
            if mode == "strict":
                kwargs = {"strict": True}
            else:
                kwargs = {"strict": False}
            if len(items) == 4:
                pubkey, bits, fingerprint_md5, fingerprint_sha256 = items
                options = comment = None
            else:
                pubkey, bits, fingerprint_md5, fingerprint_sha256, options, comment = items
            setattr(TestKeys, "test_%s_mode_%s" % (prefix_tmp, mode), ch(pubkey, bits, fingerprint_md5, fingerprint_sha256, options, comment, **kwargs))


def loop_invalid(keyset, prefix):
    """ Loop over list of invalid keys and dynamically create tests """
    def ch(pubkey, expected_error, **kwargs):
        return lambda self: self.check_fail(pubkey, expected_error, **kwargs)
    for i, items in enumerate(keyset):
        modes = items.pop()
        prefix_tmp = "%s_%s" % (prefix, items.pop())
        for mode in modes:
            if mode == "strict":
                kwargs = {"strict": True}
            else:
                kwargs = {"strict": False}
            pubkey, expected_error = items
            setattr(TestKeys, "test_%s_mode_%s" % (prefix_tmp, mode), ch(pubkey, expected_error, **kwargs))

loop_valid(list_of_valid_keys, "valid_key")
loop_valid(list_of_valid_keys_rfc4716, "valid_key_rfc4716")
loop_invalid(list_of_invalid_keys, "invalid_key")
loop_options(list_of_valid_options)
loop_invalid_options(list_of_invalid_options)

if __name__ == '__main__':
    unittest.main()
