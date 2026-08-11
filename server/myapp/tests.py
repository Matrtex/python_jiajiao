import re

from django.contrib.auth.hashers import check_password, identify_hasher
from django.test import SimpleTestCase

from myapp.security import generate_token, hash_password, verify_and_upgrade_password, verify_password


class StubUser:
    def __init__(self, password):
        self.password = password


class PasswordSecurityTests(SimpleTestCase):
    def test_new_password_uses_pbkdf2(self):
        encoded = hash_password('correct horse battery staple')

        self.assertEqual(identify_hasher(encoded).algorithm, 'pbkdf2_sha256')
        self.assertTrue(check_password('correct horse battery staple', encoded))
        self.assertFalse(check_password('wrong password', encoded))

    def test_legacy_md5_password_is_accepted_and_upgraded(self):
        # admin123 的存量 MD5，仅用于覆盖兼容迁移路径。
        user = StubUser('0192023a7bbd73250516f069df18b500')

        is_valid, upgraded = verify_and_upgrade_password(user, 'admin123')

        self.assertTrue(is_valid)
        self.assertTrue(upgraded)
        self.assertEqual(identify_hasher(user.password).algorithm, 'pbkdf2_sha256')
        self.assertTrue(verify_password('admin123', user.password))

    def test_invalid_legacy_password_is_not_upgraded(self):
        legacy_password = '0192023a7bbd73250516f069df18b500'
        user = StubUser(legacy_password)

        is_valid, upgraded = verify_and_upgrade_password(user, 'wrong password')

        self.assertFalse(is_valid)
        self.assertFalse(upgraded)
        self.assertEqual(user.password, legacy_password)

    def test_token_keeps_existing_wire_format(self):
        first_token = generate_token()
        second_token = generate_token()

        self.assertRegex(first_token, re.compile(r'^[0-9a-f]{32}$'))
        self.assertNotEqual(first_token, second_token)
