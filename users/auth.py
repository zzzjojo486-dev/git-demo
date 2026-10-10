import base64
import hashlib
import hmac
import time
import json

from django.contrib.auth import get_user_model
from rest_framework import authentication, exceptions

from rest_framework import authentication

secret_key = 'zds666'

def b64url(data):
    """JWT 用的 url-safe base64：去掉特殊字符、去掉 = 填充。"""
    return base64.urlsafe_b64encode(data).replace(b"=", b"").decode()


def create_token(user_id, secret_key, exp=24 * 60 * 60):
    # 1. 声明头部（算法/类型）
    header = {"alg": "HS256", "typ": "JWT"}

    # 2. 组装载荷（身份 + 过期时间戳）
    now = int(time.time())
    payload = {"sub": str(user_id), "exp": now + exp}

    # 3. 头、载荷编码成字符串
    header_b64 = b64url(json.dumps(header).encode())
    payload_b64 = b64url(json.dumps(payload).encode())

    # 4. 用密钥对"头.载荷"算签名【点 . 连接】
    signing_input = f"{header_b64}.{payload_b64}"
    signature = hmac.new(secret_key.encode(), signing_input.encode(), hashlib.sha256).digest()
    signature_b64 = b64url(signature)

    # 5. 三段拼一句【记得补一个点】→ "头.载荷.签名"
    token = f"{signing_input}.{signature_b64}"
    return token


def b64url_decode(data):
    """把 b64url 编码过的字符串还原成原始字符。"""
    padding = 4 - len(data) % 4
    if padding != 4:
        data += "=" * padding
    data = data.replace("-", "+").replace("_", "/")
    return base64.b64decode(data.encode()).decode()


def verify_token(token, secret_key):
    try:
        # 1. 先按点拆成三段
        part1, part2, part3 = token.split(".")

        # 2. 重新用密钥算签名，跟第三段比对【这是防伪核心】
        signing_input = f"{part1}.{part2}"
        expected = b64url(hmac.new(secret_key.encode(), signing_input.encode(), hashlib.sha256).digest())
        if expected != part3:
            return None  # 签名对不上 = 被改动/伪造

        # 3. 还原载荷，检查是否过期
        payload = json.loads(b64url_decode(part2))
        if payload["exp"] < int(time.time()):
            return None  # 过期
        return payload
    except Exception:
        return None

class BearerTokenAuthentication(authentication.BaseAuthentication):
    keyword = 'Bearer'
    def authenticate(self, request):
        header = authentication.get_authorization_header(request)
        if not header:
            return None
        parts = header.split()
        if len(parts) != 2 or parts[0].lower() != self.keyword:
            return None
        token = parts[1]

        payload = verify_token(token, secret_key)
        if payload is None:
            raise exceptions.AuthenticationFailed("无效的认证令牌")  # 验不过 → 401

        user_id = int(payload['sub'])
        user_model = get_user_model()
        try:
            user = user_model.objects.get(pk=user_id)
        except user_model.DoesNotExist:
            raise exceptions.AuthenticationFailed("用户不存在")

        return user,token
