""" Creates tests from lists of both valid and invalid keys.

New test is generated for each key so that running unittests gives out meaningful errors.

"""

from .authorized_keys import items as list_of_authorized_keys
from .invalid_authorized_keys import items as list_of_invalid_authorized_keys
from .invalid_keys import keys as list_of_invalid_keys
from .invalid_options import options as list_of_invalid_options
from .valid_keys import keys as list_of_valid_keys
from .valid_keys_rfc4716 import keys as list_of_valid_keys_rfc4716
from .valid_options import options as list_of_valid_options
from sshpubkeys import AuthorizedKeysFile, InvalidOptionsError, SSHKey

import sys
import unittest

if sys.version_info.major == 2:
    from io import BytesIO as StringIO
else:
    from io import StringIO

DEFAULT_KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEGODBKRjsFB/1v3pDRGpA6xR+QpOJg9vat0brlbUNDD"


class TestMisc(unittest.TestCase):
    def test_none_to_constructor(self):
        ssh = SSHKey(None)
        self.assertEqual(None, ssh.keydata)  # Python2.6 does not have assertIsNone
        self.assertRaises(ValueError, ssh.parse)


class TestKeys(unittest.TestCase):
    def check_key(self, pubkey, bits, fingerprint_md5, fingerprint_sha256, options, comment, **kwargs):  # pylint:disable=too-many-arguments
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

    def test_disallow_options(self):
        ssh = SSHKey(disallow_options=True)
        key = """command="dump /home",no-pty,no-port-forwarding """ + DEFAULT_KEY
        self.assertRaises(InvalidOptionsError, ssh.parse, key)


class TestAuthorizedKeys(unittest.TestCase):
    def check_valid_file(self, file_str, valid_keys_count):
        file_obj = StringIO(file_str)
        key_file = AuthorizedKeysFile(file_obj)
        for item in key_file.keys:
            self.assertIsInstance(item, SSHKey)
        self.assertEqual(len(key_file.keys), valid_keys_count)

    def check_invalid_file(self, file_str, expected_error):
        file_obj = StringIO(file_str)
        self.assertRaises(expected_error, AuthorizedKeysFile, file_obj)

    def test_disallow_options(self):
        file_obj = StringIO("""command="dump /home",no-pty,no-port-forwarding """ + DEFAULT_KEY)
        self.assertRaises(InvalidOptionsError, AuthorizedKeysFile, file_obj, disallow_options=True)
        file_obj.seek(0)
        key_file = AuthorizedKeysFile(file_obj)
        self.assertEqual(len(key_file.keys), 1)


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

    def ch(pubkey, bits, fingerprint_md5, fingerprint_sha256, options, comment, **kwargs):  # pylint:disable=too-many-arguments
        return lambda self: self.check_key(pubkey, bits, fingerprint_md5, fingerprint_sha256, options, comment, **kwargs)

    for items in keyset:
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
            setattr(
                TestKeys, "test_%s_mode_%s" % (prefix_tmp, mode),
                ch(pubkey, bits, fingerprint_md5, fingerprint_sha256, options, comment, **kwargs)
            )


def loop_invalid(keyset, prefix):
    """ Loop over list of invalid keys and dynamically create tests """

    def ch(pubkey, expected_error, **kwargs):
        return lambda self: self.check_fail(pubkey, expected_error, **kwargs)

    for items in keyset:
        modes = items.pop()
        prefix_tmp = "%s_%s" % (prefix, items.pop())
        for mode in modes:
            if mode == "strict":
                kwargs = {"strict": True}
            else:
                kwargs = {"strict": False}
            pubkey, expected_error = items
            setattr(TestKeys, "test_%s_mode_%s" % (prefix_tmp, mode), ch(pubkey, expected_error, **kwargs))


def loop_authorized_keys(keyset):
    def ch(file_str, valid_keys_count):
        return lambda self: self.check_valid_file(file_str, valid_keys_count)

    for i, items in enumerate(keyset):
        prefix_tmp = "%s_%s" % (items[0], i)
        setattr(TestAuthorizedKeys, "test_%s" % prefix_tmp, ch(items[1], items[2]))


def loop_invalid_authorized_keys(keyset):
    def ch(file_str, expected_error, **kwargs):
        return lambda self: self.check_invalid_file(file_str, expected_error, **kwargs)

    for i, items in enumerate(keyset):
        prefix_tmp = "%s_%s" % (items[0], i)
        setattr(TestAuthorizedKeys, "test_invalid_%s" % prefix_tmp, ch(items[1], items[2]))


loop_valid(list_of_valid_keys, "valid_key")
loop_valid(list_of_valid_keys_rfc4716, "valid_key_rfc4716")
loop_invalid(list_of_invalid_keys, "invalid_key")
loop_options(list_of_valid_options)
loop_invalid_options(list_of_invalid_options)
loop_authorized_keys(list_of_authorized_keys)
loop_invalid_authorized_keys(list_of_invalid_authorized_keys)

if __name__ == '__main__':
    unittest.main()
