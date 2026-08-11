# Create your views here.
import datetime

from rest_framework.decorators import api_view, authentication_classes

from myapp import utils
from myapp.auth.authentication import TokenAuthtication
from myapp.handler import APIResponse
from myapp.models import User
from myapp.security import generate_token, hash_password, verify_and_upgrade_password, verify_password
from myapp.serializers import UserSerializer, LoginLogSerializer


def make_login_log(request):
    try:
        username = request.data['username']
        data = {
            "username": username,
            "ip": utils.get_ip(request),
            "ua": utils.get_ua(request)
        }
        serializer = LoginLogSerializer(data=data)
        if serializer.is_valid():
            serializer.save()
        else:
            print(serializer.errors)
    except Exception as e:
        print(e)


@api_view(['POST'])
def login(request):
    username = request.data['username']
    raw_password = request.data['password']

    user = None
    password_upgraded = False
    for candidate in User.objects.filter(username=username):
        password_valid, password_upgraded = verify_and_upgrade_password(candidate, raw_password)
        if password_valid:
            user = candidate
            break

    if user is not None:
        if user.role in ['1', '3']:
            return APIResponse(code=1, msg='该帐号为后台管理员帐号')

        user.token = generate_token()
        update_fields = ['token']
        if password_upgraded:
            update_fields.append('password')
        user.save(update_fields=update_fields)

        serializer = UserSerializer(user)
        make_login_log(request)
        return APIResponse(code=0, msg='登录成功', data=serializer.data)

    return APIResponse(code=1, msg='用户名或密码错误')


@api_view(['POST'])
def register(request):
    print(request.data)
    username = request.data.get('username', None)
    password = request.data.get('password', None)
    repassword = request.data.get('repassword', None)
    if not username or not password or not repassword:
        return APIResponse(code=1, msg='用户名或密码不能为空')
    if password != repassword:
        return APIResponse(code=1, msg='密码不一致')
    users = User.objects.filter(username=username)
    if len(users) > 0:
        return APIResponse(code=1, msg='该用户名已存在')

    data = {
        'username': username,
        'password': password,
        'role': 2,  # 角色2
        'status': 0,
    }
    data.update({'password': hash_password(request.data['password'])})
    serializer = UserSerializer(data=data)
    if serializer.is_valid():
        serializer.save()
        return APIResponse(code=0, msg='创建成功', data=serializer.data)
    else:
        print(serializer.errors)

    return APIResponse(code=1, msg='创建失败')


@api_view(['GET'])
def info(request):
    if request.method == 'GET':
        pk = request.GET.get('id', -1)
        user = User.objects.get(pk=pk)
        serializer = UserSerializer(user)
        return APIResponse(code=0, msg='查询成功', data=serializer.data)


@api_view(['POST'])
@authentication_classes([TokenAuthtication])
def update(request):
    try:
        pk = request.GET.get('id', -1)
        user = User.objects.get(pk=pk)
    except User.DoesNotExist:
        return APIResponse(code=1, msg='对象不存在')

    data = request.data.copy()
    if 'username' in data.keys():
        del data['username']
    if 'password' in data.keys():
        del data['password']
    if 'role' in data.keys():
        del data['role']
    serializer = UserSerializer(user, data=data)
    print(serializer.is_valid())
    if serializer.is_valid():
        serializer.save()
        return APIResponse(code=0, msg='更新成功', data=serializer.data)
    else:
        print(serializer.errors)

    return APIResponse(code=1, msg='更新失败')


@api_view(['POST'])
@authentication_classes([TokenAuthtication])
def updatePwd(request):

    try:
        pk = request.GET.get('id', -1)
        user = User.objects.get(pk=pk)
    except User.DoesNotExist:
        return APIResponse(code=1, msg='对象不存在')

    print(user.role)
    if user.role != '2':
        return APIResponse(code=1, msg='参数非法')

    password = request.data.get('password', None)
    newPassword1 = request.data.get('newPassword1', None)
    newPassword2 = request.data.get('newPassword2', None)

    if not password or not newPassword1 or not newPassword2:
        return APIResponse(code=1, msg='不能为空')

    if not verify_password(password, user.password):
        return APIResponse(code=1, msg='原密码不正确')

    if newPassword1 != newPassword2:
        return APIResponse(code=1, msg='两次密码不一致')

    user.password = hash_password(newPassword1)
    user.save(update_fields=['password'])
    serializer = UserSerializer(user)
    return APIResponse(code=0, msg='更新成功', data=serializer.data)
