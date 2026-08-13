import hashlib
import hmac
import secrets

from django.contrib.auth.hashers import check_password, make_password


def _is_legacy_md5(encoded_password):
    """识别旧数据库中的 32 位无盐 MD5。"""
    if not isinstance(encoded_password, str) or len(encoded_password) != 32:
        return False
    return all(character in '0123456789abcdefABCDEF' for character in encoded_password)


def hash_password(raw_password):
    """使用 Django 首选算法生成带盐密码哈希。"""
    return make_password(raw_password)


def verify_password(raw_password, encoded_password):
    """校验当前强哈希或存量无盐 MD5 密码。"""
    if _is_legacy_md5(encoded_password):
        legacy_hash = hashlib.md5(raw_password.encode('utf-8')).hexdigest()
        return hmac.compare_digest(legacy_hash, encoded_password.lower())
    return check_password(raw_password, encoded_password)


def verify_and_upgrade_password(user, raw_password):
    """校验密码，并在内存中把存量弱哈希升级为首选算法。"""
    if _is_legacy_md5(user.password):
        if not verify_password(raw_password, user.password):
            return False, False
        user.password = make_password(raw_password)
        return True, True

    upgraded_password = None

    def upgrade(password):
        nonlocal upgraded_password
        upgraded_password = make_password(password)

    is_valid = check_password(raw_password, user.password, setter=upgrade)
    if is_valid and upgraded_password is not None:
        user.password = upgraded_password
        return True, True

    return is_valid, False


def generate_token():
    """生成与现有数据库字段和前端协议兼容的 32 位随机令牌。"""
    return secrets.token_hex(16)
