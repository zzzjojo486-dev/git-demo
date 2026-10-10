from rest_framework.views import APIView

from rest_framework import status
from rest_framework.response import Response

from users.auth import create_token
from users.models import User
from users.serializers import UserSerializer, RegistrationSerializer, LoginSerializer


secret_key = 'zds666'


class RegisterView(APIView):
    def post(self, request):
        serializer = RegistrationSerializer(data=request.data)
        if not serializer.is_valid():
            return Response({"success": "False", "message": list(serializer.errors.values())[0]},
                            status=status.HTTP_400_BAD_REQUEST)
        username = serializer.validated_data["username"]
        password = serializer.validated_data["password"]
        nickname = serializer.validated_data.get("nickname", "")
        User.objects.create_user(username=username, password=password, nickname=nickname)
        return Response({"success": "True", "message": "User Created"}, status=status.HTTP_201_CREATED)


class LoginView(APIView):
    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        if not serializer.is_valid():
            return Response({"success": "False", "message": "参数错误"}, status=status.HTTP_400_BAD_REQUEST)
        username = serializer.validated_data["username"]
        password = serializer.validated_data["password"]
        user = User.objects.filter(username=username).first()
        if not user:
            return Response({"success": "False", "message": "用户不存在"}, status=status.HTTP_400_BAD_REQUEST)
        if not user.check_password(password):
            return Response({"success": "False", "message": "密码或用户名错误"}, status=status.HTTP_400_BAD_REQUEST)
        token = create_token(user.id, secret_key)
        return Response({"success": "True", "token": token, "user": UserSerializer(user).data},
                        status=status.HTTP_200_OK)
