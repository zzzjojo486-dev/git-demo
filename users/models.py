from django.contrib.auth.base_user import BaseUserManager, AbstractBaseUser
from django.db import models

# Create your models here.
from django.db import models
from django.contrib.auth.models import AbstractUser


class UserManager(BaseUserManager):
    def create_user(self, username, password, nickname=None, **extra_fields):
        user = self.model(username=username, nickname=nickname, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

# 我们的用户表：继承 Django 自带的"用户模板" AbstractUser
class User(AbstractUser):
    # Django 已经替我们带好了这些字段（不用重复写）：
    #   username  用户名（登录用，唯一）
    #   password  密码（Django自动加密存哈希）
    #   email     邮箱
    #   first_name/last_name  姓名
    #   is_staff / is_active   状态
    #   date_joined 注册时间
    #   ...

    # 我们自己额外加一个字段：昵称（显示用，可空）
    nickname = models.CharField(max_length=50, blank=True, null=True)
    objects = UserManager()

