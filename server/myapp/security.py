import secrets

from django.contrib.auth.hashers import check_password, make_password


def hash_password(raw_password):
    """使用 Django 首选算法生成带盐密码哈希。"""
    return make_password(raw_password)


def verify_password(raw_password, encoded_password):
    """校验 Django 支持的强密码哈希。"""
    return check_password(raw_password, encoded_password)


def verify_and_upgrade_password(user, raw_password):
    """校验密码，并在内存中把存量弱哈希升级为首选算法。"""
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
