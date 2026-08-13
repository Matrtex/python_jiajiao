import re
from unittest.mock import MagicMock, patch

from django.contrib.auth.hashers import check_password, identify_hasher
from django.test import SimpleTestCase
from django.urls import resolve
from rest_framework.test import APIRequestFactory

from myapp.security import generate_token, hash_password, verify_and_upgrade_password, verify_password
from myapp.views.index import classification as classification_views
from myapp.views.index import user as user_views


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


class ApiCompatibilitySmokeTests(SimpleTestCase):
    def setUp(self):
        self.factory = APIRequestFactory()

    def test_login_endpoint_dispatches_request(self):
        request = self.factory.post(
            '/myapp/index/user/login',
            {'username': 'missing-user', 'password': 'invalid-password'},
            format='json',
        )

        with patch.object(user_views.User.objects, 'filter', return_value=[]):
            response = user_views.login(request)

        self.assertEqual(resolve('/myapp/index/user/login').url_name, None)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data['code'], 1)

    def test_register_endpoint_validates_required_fields(self):
        request = self.factory.post(
            '/myapp/index/user/register',
            {'username': 'new-user', 'password': 'new-password'},
            format='json',
        )

        response = user_views.register(request)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data['code'], 1)

    def test_classification_endpoint_serializes_queryset(self):
        queryset = MagicMock()
        serializer = MagicMock(data=[])
        request = self.factory.get('/myapp/index/classification/list')

        with (
            patch.object(
                classification_views.Classification.objects,
                'all',
                return_value=MagicMock(order_by=MagicMock(return_value=queryset)),
            ),
            patch.object(classification_views, 'ClassificationSerializer', return_value=serializer),
        ):
            response = classification_views.list_api(request)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data, {'code': 0, 'msg': '查询成功', 'data': []})
