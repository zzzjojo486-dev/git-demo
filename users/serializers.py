
from rest_framework import serializers

from users.models import User


class RegistrationSerializer(serializers.Serializer):

    username = serializers.CharField()
    password = serializers.CharField()
    nickname = serializers.CharField(required=False,allow_blank=True)

    def validate_username(self, value):
        username = value.strip()
        if User.objects.filter(username=username).exists():
            raise serializers.ValidationError("此用户已存在")
        if len(username) < 3 or len(username) > 12:
            raise serializers.ValidationError("用户名至少需要三个字符")
        return username

    def validate_password(self, value):
        password = value.strip()
        if len(password) < 6 :
            raise serializers.ValidationError("密码至少6个字符")
        has_letter = any(c.isalpha() for c in password)
        has_digit = any(c.isdigit() for c in password)

        if not (has_letter and has_digit):
            raise serializers.ValidationError("密码必须包含字母+数字组合")
        return password


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('id', 'username','nickname' )


class LoginSerializer(serializers.Serializer):
    username = serializers.CharField()
    password = serializers.CharField()
    