from rest_framework import serializers
from .models import *
from django.contrib.auth import authenticate
from django.utils import timezone
from django.conf import settings
 
import random
import string
from .helper import send_email
 
class UserRegistrationSerializer(serializers.ModelSerializer):
    last_login = serializers.DateTimeField(read_only=True)
    trial_end_date = serializers.DateTimeField(read_only=True)
 
    class Meta:
        model = Users
        fields = ['username', 'first_name', 'last_name', 'email', 'last_login', 'trial_end_date']
 
    def generate_random_password(self, length=10):
        chars = string.ascii_letters + string.digits  # Only letters and digits
        return ''.join(random.choice(chars) for _ in range(length))
 
    def create(self, validated_data):
        random_password = self.generate_random_password()
 
        user = Users.objects.create_user(
            username=validated_data['username'],
            first_name=validated_data['first_name'],
            last_name=validated_data['last_name'],
            email=validated_data['email'],
            password=random_password,
        )
 
        user.last_login = timezone.now()
        user.trial_end_date = timezone.now() + timezone.timedelta(days=7)
        user.save()
        Client_email = user.email
        message = f"""Hi {user.first_name},
 
Your account has been created successfully.
 
Here is your:
Email: {user.email}
Password: {random_password}
 
Please change it after login.
 
Login here: {settings.WEBSITE_URL}"""
        send_email(
            Client_email,
            "Welcome to Zenflows!",
            message,
        )
        return user
    
class UserLoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)
 
    def validate(self, data):
        email = data.get('email')
        password = data.get('password')
        user = authenticate(username=email, password=password)
        if user and user.is_active:
            user.last_login = timezone.now()
            user.save()
            
            return user
        raise serializers.ValidationError("Invalid credentials")
    
 
 
class EmailSerializer(serializers.ModelSerializer):
    class Meta:
        model = Email
        fields = '__all__'
 
 
class SentEmailSerializer(serializers.ModelSerializer):
    class Meta:
        model = SentEmail
        fields = '__all__'
 
 
 
class UserAccountSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserAccount
        fields = ['id','email', 'access_token','account_type']
 
 
class ClientSerializer(serializers.ModelSerializer):
    class Meta:
        model = Users
        fields = ['id', 'username', 'email', 'first_name', 'last_name', 'date_joined', 'is_active','password']
 
class NotificationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Notification
        fields = ['id', 'message', 'notification_type', 'created_at', 'read']
 
 
 
 
class UserUpdateSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=False)
 
    class Meta:
        model = Users
        fields = ['id', 'username', 'first_name', 'last_name', 'email', 'password']
        extra_kwargs = {
            'email': {'read_only': True},  # if you want email to stay constant
        }
 
    def update(self, instance, validated_data):
        instance.username = validated_data.get('username', instance.username)
        instance.first_name = validated_data.get('first_name', instance.first_name)
        instance.last_name = validated_data.get('last_name', instance.last_name)
 
        # Optional: Prevent email update, or allow it by removing this line
        # instance.email = validated_data.get('email', instance.email)
 
        if 'password' in validated_data and validated_data['password']:
            instance.set_password(validated_data['password'])
 
        instance.save()
        return instance
class ClientRegisterSerializer(serializers.ModelSerializer):
    # email = serializers.EmailField(required=True)
    # username = serializers.CharField(required=True)
    # password = serializers.CharField(write_only=True, required=True)
    # last_login = serializers.DateTimeField(read_only=True)
    # trial_end_date = serializers.DateTimeField(read_only=True)

    class Meta:
        model = Users
        fields = '__all__'

    def validate_email(self, value):
        if Users.objects.filter(email=value).exists():
            raise serializers.ValidationError("A user with this email already exists.")
        return value

    def create(self, validated_data):
        user = Users.objects.create_user(
            username=validated_data['username'],
            email=validated_data['email'],
            password=validated_data['password'],
            first_name=validated_data.get('first_name', ''),
            last_name=validated_data.get('last_name', '')
        )
        user.last_login = timezone.now()
        user.trial_end_date = timezone.now() + timezone.timedelta(days=7)
        user.save()
        Client_email = user.email
        message = f"""Hi {user.first_name},
 
Your account has been created successfully.

Please change it after login.
 
"""
        send_email(
            Client_email,
            "Welcome to Zenflows!",
            message,
        )
        return user