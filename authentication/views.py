from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from outlook.utils import send_outlook_reply,send_incident_reply
from shopify.models import ShopifyStore
from django.db.models import Sum
from subscriptions.models import Subscription, UserSubscription
from .models import *
from django.views.decorators.csrf import csrf_exempt
from django.conf import settings
from django.http import JsonResponse
from rest_framework.pagination import PageNumberPagination
from django.db.models import Q
from django.utils import timezone
import requests
from .serializers import *
from authentication.tasks import refresh_access_token
import base64
import urllib.parse
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from google.auth.transport import requests as google_requests
from google.oauth2 import id_token
from django.contrib.auth import get_user_model
from rest_framework.permissions import IsAuthenticated
from urllib.parse import urlencode
import json
import re
import openai
openai.api_key = settings.OPENAI_API_KEY  
from .helper import *
from django.utils.crypto import get_random_string
from imap.utils import send_imap_reply,send_imap_email_reply

import threading
from ai.views import FAQView
import textwrap
# In views.py
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .models import Notification, Users

from datetime import timedelta
from django.utils.timezone import now


# User Register
class UserRegistrationView(APIView):
    def post(self, request):
        serializer = UserRegistrationSerializer(data=request.data)
        if serializer.is_valid():
            try:
                user = serializer.save()
                return Response({
                    "status_code": status.HTTP_201_CREATED,
                    "message": "User registered successfully.",
                    "data": {
                        "id": user.id,
                        "username": user.username,
                        "email": user.email,
                        "first_name": user.first_name,
                        "last_name": user.last_name,
                    }
                }, status=status.HTTP_201_CREATED)

            except Exception as e:
                return Response({
                    "status_code": status.HTTP_500_INTERNAL_SERVER_ERROR,
                    "message": "Something went wrong while registering the user.",
                    "data": None
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        return Response({
            "status_code": status.HTTP_400_BAD_REQUEST,
            "message":  serializer.errors,
            "data":"None"
        }, status=status.HTTP_400_BAD_REQUEST)
    

##############
# User Registration
 
class ClientRegister(APIView):
    def post(self, request):
        # print("ENTER HERE",request.data)
        serializer = ClientRegisterSerializer(data=request.data)
        # print('serializer',serializer)
        if serializer.is_valid():
            user = serializer.save()
            # data = serializer.data
            # user = Users.objects.create(
            #     username=data['username'],
            #     email=data['email'],
            #     password=data['password'],
            #     first_name=data['first_name'],
            #     last_name=data['last_name'],
            # )
            # print("user",user)
            # user.last_login = timezone.now()
            # user.trial_end_date = timezone.now() + timezone.timedelta(days=7)
            # print("before save",user.trial_end_date)
            # user.save()
            # print("after save",user.trial_end_date)

            return Response({
                "success": True,
                "message": "User registered successfully.",
                'data':serializer.data,
                "status_code": status.HTTP_201_CREATED
            }, status=status.HTTP_201_CREATED)

        return Response({
            "success": False,
            "message": "Registration failed.",
            "errors": serializer.errors,
            "status_code": status.HTTP_200_OK
        }, status=status.HTTP_200_OK)
# Client Listing

# Client Listing
class ClientListView(APIView):
    def get(self, request):
        try:
            user_id = request.query_params.get("user_id", None)
            if not user_id:
                return Response(
                    {
                        "status": "error",
                        "message": "User ID is required.",
                        "code": 400,
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )
 
            # Verify if the logged-in user is a superuser
            try:
                requesting_user = Users.objects.get(id=user_id)
                if not requesting_user.is_superuser:
                    return Response(
                        {
                            "status": "error",
                            "message": "Permission denied. Only superusers can access this.",
                            "code": 403,
                        },
                        status=status.HTTP_403_FORBIDDEN,
                    )
            except Users.DoesNotExist:
                return Response(
                    {
                        "status": "error",
                        "message": "User not found.",
                        "code": 404,
                    },
                    status=status.HTTP_404_NOT_FOUND,
                )
 
            search_query = request.query_params.get("search", None)
 
            # Filter users where is_deleted is False
            users = Users.objects.filter(is_deleted=False, is_superuser=False)
 
            # Apply search if query is provided
            if search_query:
                users = users.filter(
                    Q(username__icontains=search_query) |
                    Q(email__icontains=search_query)
                )
 
            user_count = users.count()  # Get count of users
 
            # Implement pagination
            paginator = PageNumberPagination()
            result_page = paginator.paginate_queryset(users, request)
 
            serializer = ClientSerializer(result_page, many=True)
 
            return paginator.get_paginated_response({
                "status": "success",
                "message": "Users retrieved successfully.",
                "code": 200,
                "user_count": user_count,
                "data": serializer.data,
            })
        except Exception as e:
            return Response(
                {
                    "status": "error",
                    "message": "An error occurred while fetching users.",
                    "code": 500,
                    "error": str(e),
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )
        
class ClientDetailView(APIView):
    def get(self, request, user_id):
        try:
            user = Users.objects.get(id=user_id)
            serializer = ClientSerializer(user)
            return Response({
                "status": "success",
                "message": "User retrieved successfully.",
                "code": 200,
                "data": serializer.data
            }, status=status.HTTP_200_OK)
        except Users.DoesNotExist:
            return Response({
                "status": "error",
                "message": "User not found.",
                "code": 404
            }, status=status.HTTP_404_NOT_FOUND)

    def put(self, request, user_id):
        try:
            user = Users.objects.get(id=user_id)
            serializer = ClientSerializer(user, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response(
                    {
                        "status": "success",
                        "message": "User updated successfully.",
                        "code": 200,
                        "data": serializer.data,
                    },
                    status=status.HTTP_200_OK,
                )
            return Response(
                {
                    "status": "error",
                    "message": "Invalid data.",
                    "code": 400,
                    "errors": serializer.errors,
                },
                status=status.HTTP_400_BAD_REQUEST,
            )
        except Users.DoesNotExist:
            return Response(
                {"status": "error", "message": "User not found.", "code": 404},
                status=status.HTTP_404_NOT_FOUND,
            )

    def delete(self, request, user_id):
        try:
            user = Users.objects.get(id=user_id)
            user.is_deleted = True
            user.save()

            return Response(
                {
                    "status": "success",
                    "message": "Changed User deleted status.",
                    "code": 200,
                },
                status=status.HTTP_200_OK,
            )
        except Users.DoesNotExist:
            return Response({
                "status": "error",
                "message": "User not found.",
                "code": 404
            }, status=status.HTTP_404_NOT_FOUND)
 
# User Login
class UserLoginView(APIView):
    def post(self, request):
        serializer = UserLoginSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.validated_data
            
            # Check if the user is marked as deleted
            if user.is_deleted:
                return Response(
                    {
                        "status": "error",
                        "message": "User account is deleted.",
                    },
                    status=status.HTTP_403_FORBIDDEN,  # Forbidden status code
                )
            
            # # Set trial_end_date if not already set (e.g., for existing users)
            # if not user.trial_end_date:
            #     user.trial_end_date = timezone.now() + timezone.timedelta(days=7)
            #     user.save()
                
            # Check trial status manually
            trial_message = ""
            trial_expired = user.trial_end_date is None or timezone.now() > user.trial_end_date
            if trial_expired:
                trial_message = "Your 7-day free trial has expired."
            else:
                days_left = (user.trial_end_date - timezone.now()).days
                trial_message = f"Your 7-day free trial is active. {days_left} days remaining."
        
            
            refresh = RefreshToken.for_user(user)
            users = UserRegistrationSerializer(user).data
            return Response(
                {
                    "status": "success",
                    "data": {
                        "refresh": str(refresh),
                        "access": str(refresh.access_token),
                        "id": user.id,
                        "users": users,
                    },
                    "is_superuser": user.is_superuser,
                    "message": "Login successful",
                    "trial_status": trial_message,
                    "trial_expired": trial_expired,
                    "trial_days_left": days_left if not trial_expired else 0,
                    "trial_end_date": user.trial_end_date.strftime("%Y-%m-%d") if user.trial_end_date else None,
                },
                status=status.HTTP_200_OK,
            )
        return Response(
            {
                "status": "error",
                "data": serializer.errors,
                "message": "Invalid credentials",
            },
            status=status.HTTP_400_BAD_REQUEST,
        )


# User Update


class UserUpdateView(APIView):
    def get(self, request, pk):
        try:
            user = Users.objects.get(pk=pk)
        except Users.DoesNotExist:
            return Response(
                {"error": "User not found"}, status=status.HTTP_404_NOT_FOUND
            )

        serializer = UserRegistrationSerializer(user)

        # trial_status = "Trial expired" if user.is_trial_expired else f"Trial active, {(user.trial_end_date - timezone.now()).days} days left"
        print("pk", pk)
        return Response(
            {
                "user": serializer.data,
            },
            status=status.HTTP_200_OK,
        )
    def put(self, request, pk):
        try:
            user = Users.objects.get(pk=pk)
        except Users.DoesNotExist:
            return Response(
                {"error": "User not found"}, status=status.HTTP_404_NOT_FOUND
            )
        except Exception as e:
            return Response(
                {"error": "An unexpected error occurred", "details": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )
        serializer = UserUpdateSerializer(user, data=request.data, partial=True)
        if serializer.is_valid():

            serializer.save()
            # trial_status = "Trial expired" if user.is_trial_expired else f"Trial active, {(user.trial_end_date - timezone.now()).days} days left"
            return Response(
                {
                    "status": status.HTTP_200_OK,
                    "message": "User profile updated successfully.",
                    "data": serializer.data,
                },
                status=status.HTTP_200_OK,
            )
        return Response(
            {
                "status": status.HTTP_400_BAD_REQUEST,
                "message": "Failed to update user profile.",
                "errors": serializer.errors,
            },
            status=status.HTTP_400_BAD_REQUEST,
        )


### -------------------------- listing of Users  ---------------------
class UserListView(APIView):
    def get(self, request):
        try:
            search_query = request.query_params.get("search", None)

            # Apply search if query is provided
            users = Users.objects.filter(
                Q(username__icontains=search_query) | 
                Q(email__icontains=search_query)  
            ) if search_query else Users.objects.all()

            user_count = users.count()  # Get count of users

            # Implement pagination
            paginator = PageNumberPagination()
            result_page = paginator.paginate_queryset(users, request)

            serializer = ClientSerializer(result_page, many=True)

            return paginator.get_paginated_response(
                {
                    "status": "success",
                    "message": "Users retrieved successfully.",
                    "code": 200,
                    "user_count": user_count,
                    "data": serializer.data,
                }
            )

        except Exception as e:
            return Response(
                {
                    "status": "error",
                    "message": "An error occurred while fetching users.",
                    "code": 500,
                    "error": str(e),
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

from urllib.parse import quote_plus
# Google Initiate
class GoogleAuthView(APIView):
    """Generate Google OAuth URL"""

    def get(self, request):
        user_id = request.GET.get("user_id") 

        if not user_id:
            return Response({"error": "User ID is required"}, status=400)
        scope = quote_plus(
            "openid email profile "
            "https://www.googleapis.com/auth/gmail.readonly "
            "https://www.googleapis.com/auth/gmail.send"
)

        google_auth_url = (
            f"https://accounts.google.com/o/oauth2/auth"
            f"?client_id={settings.GMAIL_CLIENT_ID}"
            f"&redirect_uri={settings.GMAIL_REDIRECT_URIS}"
            f"&response_type=code"
            f"&scope={scope}"
            f"&access_type=offline"  # Ensures refresh token is received
            f"&prompt=consent"  # Forces user to give consent
            f"&state={user_id}"  # Pass user_id securely as a state parameter
        )

        return Response({"auth_url": google_auth_url})


# --------------------------------------------------------------------------------------------


from django.core.cache import cache
from django.shortcuts import redirect
import uuid

from django.http import HttpResponseRedirect
class GoogleLoginCallbackView(APIView):
    def get(self, request):
        url = "https://zenflows.ai/"
        # return redirect('/')
        # return HttpResponseRedirect(url)
        code = request.GET.get("code")
        user_id = request.GET.get("state")
        user_instance = Users.objects.get(id=user_id)
        createnotification(user_instance, "1", "alert")

        print("✅ Params received:", code, user_id)

        if not code or not user_id:
            createnotification(user_instance, "2", "alert")

            return Response({"error": "unauthorized access"}, status=400)

        token_url = "https://oauth2.googleapis.com/token"
        data = {
            
        }
        createnotification(user_instance, "3", "alert")

        try:
            createnotification(user_instance, "4", "alert")

            response = requests.post(token_url, data=data, timeout=10)
            response.raise_for_status()
            tokens = response.json()
            print("🔑 Tokens received:", tokens)
            print("🔑 Tokens received:")
            createnotification(user_instance, "5", "alert")


        except requests.exceptions.RequestException as req_err:
            print("❌ Request failed:", str(req_err))
            return Response({"error": "Token request failed", "details": str(req_err)}, status=500)
        except ValueError:
            print("❌ Failed to decode token JSON")
            return Response({"error": "Invalid token response"}, status=500)

        if "id_token" not in tokens:
            print("❌ ID token missing in response")
            return Response({"error": "Failed to get ID token"}, status=400)

        try:
            id_info = id_token.verify_oauth2_token(
                tokens["id_token"], google_requests.Request(), data["client_id"]
            )
            createnotification(user_instance, "6", "alert")

            email = id_info.get("email")
            name = id_info.get("name")
            print("📧 Email:", email, "| 👤 Name:", name)

            try:
                createnotification(user_instance, "6", "alert")

                user = Users.objects.get(id=user_id)
            except Users.DoesNotExist:
                return Response({"error": "User not found"}, status=404)

            try:
                createnotification(user_instance, "7", "alert")

                user_account = UserAccount.objects.get(email=email)
                Notification.objects.create(
                    user=user,
                    message=f"Your Google account {email} is already linked with another user.",
                    created_at=timezone.now(),
                    notification_type="alert",
                )
                createnotification(user_instance, "8", "alert")

                return HttpResponseRedirect("https://sdeiaiml.com:9047/email-inbox")

            except UserAccount.DoesNotExist:
                createnotification(user_instance, "9", "alert")

                user_account = UserAccount.objects.create(
                    user=user,
                    email=email,
                    account_type="gmail",
                    access_token=tokens["access_token"],
                    refresh_token=tokens.get("refresh_token", None),
                    last_login=timezone.now(),
                    is_logged=True,
                )
            createnotification(user_instance, "10", "alert")

            unique_token = str(uuid.uuid4())
            cache.set(unique_token, {
                "access_token": tokens["access_token"],
                "refresh_token": tokens.get("refresh_token"),
                "email": email,
                "name": name,
            }, timeout=60 * 5)

            createnotification(user_instance, "Your trial/subscription has expired. Please subscribe to continue.", "alert")
            url ="https://sdeiaiml.com:9047/email-inbox"
            response = HttpResponseRedirect(url)
            response.set_cookie("access_token", tokens["access_token"], httponly=True, max_age=3600, secure=True, samesite='None')
            response.set_cookie("email", email, httponly=True, max_age=3600, secure=True, samesite='None')
            response.set_cookie("name", name, httponly=True, max_age=3600, secure=True, samesite='None')
            setup_gmail_watch_api(access_token=tokens["access_token"])
            createnotification(user_instance, "11", "alert")

            return response

        except Exception as e:
            print("❌ Token verification or DB error:", str(e))
            return Response({"error": "OAuth2 callback failed", "details": str(e)}, status=500)
#-------------------------------------------------------------------------------------------------------------

class GetUserInfo(APIView):
    """Get user info using access token"""
    def get(self, request, id):
        try:
                user_obj = Users.objects.get(id=id)
                user_Acount_obj = UserAccount.objects.filter(user=user_obj,is_logged=True)
                serializer=UserAccountSerializer(user_Acount_obj, many=True)
                return Response(
                    {
                        "data": serializer.data,
                        "message" : "User Email Fetched Successfully"
                    },
                        status=200
                    )
        except Exception as e:
            return Response({"error": "something went wrong", "message" : str(e)}, status=400)
# -------------------------------------------------------------------------------------------------------------
class RefreshTokenView(APIView):
    def post(self, request):
        user_id = request.data.get("user_id")
        if not user_id:
            return Response({"error": "User ID is required"}, status=400)
        task = refresh_access_token.delay(user_id)             
        return Response({"task_id": task.id}, status=202)

# -------------------------------------------------------------------------------------------------------------

class GetTokenView(APIView):
    """Retrieve access token by unique token"""

    def get(self, request, token):
        # Retrieve the data from the cache using the unique token
        token_data = cache.get(token)

        # Check if token_data is None before accessing keys
        if not token_data:
            return Response({"error": "Token expired or not found"}, status=400)

        # Call setup_gmail_watch_api only if token_data is valid
        setup_gmail_watch_api(token_data["access_token"])

        # Return the access token and user info
        return Response(
            {
                "access_token": token_data["access_token"],
                "email": token_data["email"],
                "name": token_data["name"],
            }
        )

# -------------------------------------------------------------------------------------------------------------


GMAIL_HISTORY_URL = "https://www.googleapis.com/gmail/v1/users/me/history"
GMAIL_MESSAGE_URL_TEMPLATE = "https://www.googleapis.com/gmail/v1/users/me/messages/{}"
GMAIL_WATCH_URL = "https://www.googleapis.com/gmail/v1/users/me/watch"


@csrf_exempt
def setup_gmail_watch_api(access_token):

    try:
        if not access_token:
            return JsonResponse(
                {"error": "Missing access_token in headers or query params"}, status=400
            )

        if access_token.startswith("Bearer "):
            access_token = access_token.split("Bearer ")[1]

        print("Setting up Gmail Watch...")

        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json",
        }

        payload = {
            "labelIds": ["INBOX"],
            "topicName": "projects/zenflows-gmail-integration-app/topics/Push_Notification",
            "labelFilterBehavior": "INCLUDE", 
            "historyTypes": ["messageAdded"],  
        }

        response = requests.post(GMAIL_WATCH_URL, headers=headers, json=payload)
        # print(response,"RESponse")

        if response.status_code == 200:
            ResData = response.json()
            history_id = ResData.get("historyId")
            expiration = ResData.get("expiration")
            print(f"Received historyId: {history_id}, Expiration: {expiration}")

            if history_id:
                try:
                    user_account = UserAccount.objects.get(access_token=access_token)
                    user_account.history_id = history_id
                    user_account.save(update_fields=["history_id"])
                    print(f"History ID {history_id} saved for {user_account.email}")
                except UserAccount.DoesNotExist:
                    return JsonResponse(
                        {"error": "No user found for the given access token"},
                        status=404,
                    )

            return JsonResponse(
                {
                    "message": "Watch setup successful",
                    "historyId": history_id,
                    "expiration": expiration,
                },
                status=200,
            )

        else:
            print("Failed to set up Gmail watch:", response.text)
            return JsonResponse(
                {"error": "Failed to set up Gmail watch", "details": response.text},
                status=response.status_code,
            )

    except Exception as e:
        print("Error in setup_gmail_watch_api:", e)
        return JsonResponse({"error": str(e)}, status=500)



# -------------------------------------    webhook        ---------------------------------------------------------------------


processed_history_ids = set()
@csrf_exempt
def webhook(request):
    """Handles incoming Gmail Pub/Sub webhook requests."""
    if request.method != "POST":
        return JsonResponse({"error": "Invalid request"}, status=400)

    try:
        print("🔹 Received Webhook Request")
        # print("🔹 Request Headers:", request.headers)
        raw_body = request.body.decode("utf-8")
        print("🔹 Raw Request Body:", raw_body)
        if not raw_body:
            return JsonResponse({"error": "Empty request body"}, status=400)

        # Parse JSON request
        try:
            pubsub_message = json.loads(raw_body)
        except json.JSONDecodeError as e:
            print(" JSON Decode Error:", e)
            return JsonResponse({"error": "Invalid JSON format"}, status=400)

        # Handle direct JSON payload (non-Pub/Sub)
        if "emailAddress" in pubsub_message and "historyId" in pubsub_message:
            email_data = pubsub_message
        else:
            # Process Pub/Sub Base64-encoded message
            message_data = pubsub_message.get("message", {})
            if "data" not in message_data:
                print(" Missing 'data' field in Pub/Sub message")
                return JsonResponse({"error": "Invalid message format"}, status=400)

            try:
                encoded_data = message_data["data"]
                decoded_data = base64.b64decode(encoded_data).decode("utf-8")
                email_data = json.loads(decoded_data)
            except (base64.binascii.Error, json.JSONDecodeError) as e:
                
                return JsonResponse({"error": "Invalid Base64 or JSON format"}, status=400)

        # Extract email address & history ID
        receiver_email = email_data.get("emailAddress")
        history_id = email_data.get("historyId")

        if not receiver_email or not history_id:
            print(" Missing email or historyId in webhook payload")
            return JsonResponse({"error": "Invalid message format"}, status=400)

        history_id = str(history_id)  # Ensure string format for set operations

        print(f" New Email → Receiver: {receiver_email}, History ID: {history_id}")

        # Ignore duplicate history IDs
        if history_id in processed_history_ids:
            print(f" Ignoring Duplicate History ID: {history_id}")
            return JsonResponse({"status": "duplicate"}, status=200)

        # Maintain only the latest 100 history IDs
        if len(processed_history_ids) >= 100:
            processed_history_ids.pop()

        processed_history_ids.add(history_id)

        # Check if the email belongs to a registered user
        try:
            user_account = UserAccount.objects.get(email=receiver_email)
            access_token = user_account.access_token
            print(f" Processing Email for {receiver_email}")

            # Fetch emails using Gmail API
            fetch_and_store_emails(access_token, history_id)

            return JsonResponse({"status": "success"}, status=200)

        except UserAccount.DoesNotExist:
            print(f" Skipping: No registered user found for {receiver_email}")
            return JsonResponse({"error": "User not found"}, status=404)

    except Exception as e:
        print(" Webhook Processing Error:", str(e))
        return JsonResponse({"error": str(e)}, status=500)



# -------------------------------------------------------------------------------------------------------------

def fetch_and_store_emails(access_token, history_id):
    """Fetches new emails from Gmail API based on history ID and stores them in the database."""
    try:
        user_account = UserAccount.objects.get(access_token=access_token,is_logged=True)

        previous_history_id = int(user_account.history_id) if user_account.history_id else 0
        current_history_id = int(history_id)

        if current_history_id <= previous_history_id:
            print(f"⚠ Skipping duplicate or outdated history ID: {history_id}")
            return

        print(f" Fetching emails from Gmail API for historyId: {history_id}")

        headers = {"Authorization": f"Bearer {access_token}"}
        params = {"startHistoryId": previous_history_id, "historyTypes": ["messageAdded"]}

        response = requests.get(GMAIL_HISTORY_URL, headers=headers, params=params)

        if response.status_code == 200:
            history_data = response.json()
            # print(" Full Gmail API Response:", json.dumps(history_data, indent=2))  # Debugging

            history_records = history_data.get("history", [])

            if not history_records:
                print(f"⚠ No new emails found for history ID {history_id}. Not updating history_id.")
                return

            for record in history_records:
                messages_added = record.get("messagesAdded", [])
                for msg_entry in messages_added:
                    message_id = msg_entry["message"]["id"]
                    print(f" Processing Message ID: {message_id}")
                    store_email_in_db(message_id, access_token)

            # Update history_id **only after processing emails**
            if current_history_id > int(user_account.history_id or 0):
                user_account.history_id = current_history_id
                user_account.save(update_fields=["history_id"])
                print(f" Updated history_id to {current_history_id} for {user_account.email}")
            else:
                print(f" Skipped history_id update: current {current_history_id} <= existing {user_account.history_id}")
        else:
            print(f" Failed to fetch email history: {response.status_code} - {response.text}")

    except UserAccount.DoesNotExist:
        print(" User account not found for the given access token")
    except Exception as e:
        print(" Error fetching emails:", str(e))
# -------------------------------------------------------------------------------------------------------------



def store_email_in_db(message_id, access_token):

    headers = {"Authorization": f"Bearer {access_token}"}
    url = GMAIL_MESSAGE_URL_TEMPLATE.format(message_id)
    # print("In store_email func", headers, url)

    user_account = UserAccount.objects.get(access_token=access_token)
    account_id = user_account.id
    # print("account_id", account_id)

    response = requests.get(url, headers=headers)
    # print("Response:full message", response.json)
    if response.status_code == 200:
        email_data = response.json()
        thread_id = email_data.get("threadId", "")
        payload = email_data.get("payload", {})
        headers_list = payload.get("headers", [])
        sender = ""
        recipients = ""
        subject = ""
        original_message_id = ""
        for header in headers_list:
            name = header.get("name", "").lower()
            if name == "from":
                value = header.get("value", "")
                # Use regex to extract only the email address
                match = re.search(r"<(.+?)>", value)
                if match:
                    sender = match.group(1)  # This will capture the email address
                else:
                    sender = value  # In case the format is different (e.g., just the email without angle brackets)
            elif name == "to":
                recipients = header.get("value", "")
            elif name == "subject":
                subject = header.get("value", subject)
            elif name == "message-id":
                original_message_id = header.get("value", "")
                print("original_message_id",original_message_id)
                
        snippet = email_data.get("snippet", "")
        history_id = email_data.get("historyId", "")
        print("sender",sender)
        if sender == user_account.email:
            print(f"Skipping auto-reply email from {sender} to {recipients}")
            return  

        print("history_id",history_id)
        # Create or update the email record in the database
        email_obj, created = Email.objects.update_or_create(
            message_id=message_id,
            account_id=account_id,
            defaults={
                "subject": subject,
                "snippet": snippet,
                "history_id": history_id,
                "sender": sender,
                "recipients": recipients,
            },
        )  
        if created:
            print("Mail Successfully Saved to the Database")
            if sender:
                print("Genrating AI response and Sending Auto Reply....")
                try:
                    user_account = UserAccount.objects.get(access_token=user_account.access_token)
                    user_id = user_account.user.id  # Fetch the related user’s ID
                   
                except UserAccount.DoesNotExist:
                    print("UserAccount not found for the given access token")
                except Exception as e:
                    print(f"Error: {e}")
                threading.Timer(100, send_ai_response, args=[user_id,user_account.access_token, sender,snippet,message_id,original_message_id,thread_id,subject]).start()
            else:
                print(" Auto-reply failed: No sender found")
        else:
            print("Email already exists, skipping auto-reply")

    else:
        print("Failed to fetch email details:", response.text)

# -------------------------------------------------------------------------------------------------------------

from openai import OpenAI
client = OpenAI(api_key=settings.OPENAI_API_KEY)
def send_ai_response(user_id, access_token, recipient_email, snippet, message_id, original_message_id, thread_id, subject):
    print(f"Recipient: {recipient_email}, {message_id}, {original_message_id}")

    try:
        user_instance = Users.objects.get(id=user_id)
    except Users.DoesNotExist:
        print("User not found")
        return

    user_email = user_instance.email
    trail_end = user_instance.trial_end_date
    is_trial_active = trail_end and trail_end >= timezone.now()

    # Fetch subscription if active and not expired
    user_subscription_qs = UserSubscription.objects.filter(user_id=user_id, active=True, expires_at__gte=timezone.now())
    has_subscription = user_subscription_qs.exists()

    if not has_subscription and not is_trial_active:
        Email.objects.filter(message_id=message_id).update(is_incident=True)
        createnotification(user_instance, "Your trial/subscription has expired. Please subscribe to continue.", "alert")
        print("user_email",user_email)
        send_email(user_email, subject, "Your trial/subscription has expired. Please subscribe to continue.")
        return

    # Trial user - check trial email limit
    if is_trial_active and not has_subscription:
        if user_instance.trial_email_count >= user_instance.trial_email_limit:
            Email.objects.filter(message_id=message_id).update(is_incident=True)
            createnotification(user_instance, "You have used all 5 trial emails. Please subscribe to continue.", "alert")
            send_email(user_email, subject, "You have used all 5 trial emails. Please subscribe to continue.")
            return
        else:
            user_instance.trial_email_count += 1
            user_instance.save()

    # Subscribed user - check email limit
    if has_subscription:
        user_subscription = user_subscription_qs.first()
        if user_subscription.email_count >= user_subscription.email_limit:
            print(" Subscription email limit reached")
            Email.objects.filter(message_id=message_id).update(is_incident=True)
            createnotification(user_instance, "You have reached your email limit. Please upgrade your plan.", "alert")
            send_email(user_email, subject, "You have reached your email limit. Please upgrade your plan.")
            return
    try:
        user_account = UserAccount.objects.get(access_token=access_token)
        account_id = user_account.id
    except UserAccount.DoesNotExist:
        print(" UserAccount not found for access token")
        return


    clientID = user_id
    user_query = snippet
    order_id_match = re.search(r"\b[A-Z]{2,}\d{10,}\b", user_query, re.IGNORECASE)
    try:
        subscriptions = Subscription.objects.filter(user_id=user_id)
        for sub in subscriptions:
            accounts = sub.user.accounts.all() 
            # Count sent emails within the subscription period
            sent_email_count = SentEmail.objects.filter(
                account__in=accounts,
                timestamp__gte=sub.current_period_start,
                timestamp__lte=sub.current_period_end
            ).count()
            email_limit = int(sub.metadata.get("email_limit", 100))
            break 
    except Exception as e:
        print(f"Error fetching subscription details: {e}")
        return
    faq_view = FAQView()
    faqs = faq_view.retrieve_relevant_faqs(user_query, int(clientID), top_k=3)  
    if not faqs:
        # print("aii  response")
        ai_response = f"Dear Customer,\n\nThank you for reaching out. We couldn't find an exact answer for your query. Could you provide more details so we can assist you better?\n\nBest regards,\nZenflow.ai Customer Support"
        Email.objects.filter(message_id=message_id).update(is_incident=True)
        createnotification(user_instance, "Please review the message and respond manually.", "alert")
    else:
        faqs_text = "\n\n".join(f"Q: {faq['question']}\nA: {faq['answer']}" for faq in faqs)
        prompt = f"""
        You are an AI support assistant for {clientID}. A customer has asked:
        "{user_query}"

        Here are relevant FAQs for this client:
        {faqs_text}  

        ### **Instructions:**
        - **Detect the language of the customer's query.**  
        - **Respond in the same language as the customer's question.**  
        - Generate a **professional, friendly, and informative response** using the FAQ knowledge.  
        - If no relevant FAQ fully answers the question, politely ask for more details in the same language.
        - If the user’s query seems related to order status, return this JSON:
        {{
            "status": "action_required",
            "action": "order_query"
        }}
        ---

         ### **Response Guidelines:**  
        - Start with a **polite greeting** in the detected language.  
        - Acknowledge the customer's query respectfully.  
        - Provide the **entire FAQ answer without truncation, only rephrasing for clarity**.  
        - Maintain a **professional yet warm and supportive tone**.  
        - If necessary, suggest **next steps** or invite further questions.  
        - End with a **professional closing in the detected language**.
        - Ensure the response is a **fully structured JSON object**.
        - Detect this language {user_query} and send response in this language.

        ---
 
        ## **Response Formats:**  
 
        ### **If a relevant FAQ is found:**  
 

        ## **Response Formats:**  

        ### **If a relevant FAQ is found:**  


        ```json
        {{
            "status": "success",
            "message": "Dear Customer,\n\nThank you for reaching out with your question. I’m happy to assist you!\n\n[Provide a friendly and concise answer based on the FAQ, emphasizing clarity and reassurance.]\n\nIf you need further details or have any additional questions, feel free to ask. We’re here to help!\n\nBest regards,\nZenflow.ai",
            "code": "FAQ_FOUND",
            "suggestion": "Feel free to ask any follow-up questions or explore other resources."
        }}
        If no relevant FAQ is found, genrate response in below json format

        {{
            "status": "error",
            "message": "We could not find a relevant answer in our FAQs for your query. Could you please provide more details so we can assist you better?",
            "code": "FAQ_NOT_FOUND",
            "suggestion": "Please provide more information or contact our support team directly for assistance."
        }}
         ### If query is related to order tracking:
        ```json
        {{
            "status": "action_required",
            "action": "order_query"
        }}
        ```
        Now, generate the response.
        """
        try:
            response = client.chat.completions.create(
                model="gpt-4o-mini",
                temperature=0.1,
                max_tokens=2000,
                messages=[
                    {"role": "system", "content": "You are an AI support assistant."},
                    {"role": "user", "content": prompt}
                ],
            )
            ai_response = response.choices[0].message.content
            cleaned_response = re.sub(r"```json|```", "", ai_response).strip()
            try:
                # print("ai part")
                ai_response_dict = json.loads(cleaned_response) 
                status = ai_response_dict.get("status", "").lower()  # Ensure case consistency
                message = ai_response_dict.get("message", "Default message if not found")
                
                if  status == "success":
                    # print("Success response")
                    account_type = user_account.account_type 
                    if account_type.lower() == "gmail":
                        send_auto_reply(access_token, recipient_email, message, account_id, thread_id, original_message_id, subject)
                    elif account_type.lower() == "imap":
                        send_imap_reply(access_token, recipient_email, message, account_id, subject)
                    elif account_type.lower() == "outlook":
                           print(account_type,"ACCOunt TYpe")
                           send_outlook_reply(access_token, recipient_email, message, account_id, thread_id, message_id, subject)
                if status == "error":
                    print("Error response",status)
                    Email.objects.filter(message_id=message_id).update(is_incident=True)
                    createnotification(user_instance, message, "alert")
                # else:
                #     print(f"Unknown account type: {account_type}")
                if status == "action_required" and ai_response_dict.get("action") == "order_query":
                    order_result = handle_order_query(
                    order_id=None,
                    recipient_email=recipient_email,
                    access_token=access_token,
                    account_id=account_id,
                    message_id=message_id
                )   
                    print("order_",order_result)
                    if order_result.get("success"):
                        order_status_url = order_result.get("order_status_url", "")
                        order_message = (
                            f"Dear Customer,\n\n"
                            f"Thank you for your inquiry about your order. "
                            f"You can check your order status here:\n{order_status_url}\n\n"
                            f"Best regards,\nZenflows.ai  Support"
                                        )
                    else:
                        order_message = (
                            "Dear Customer,\n\n"
                            "We are unable to find your order details at the moment. "
                            "Please contact support for further assistance.\n\n"
                            "Best regards,\nZenflows.ai  Support"
                                        )

                    # Re-check account type and send reply accordingly
                    account_type = user_account.account_type
                    if account_type.lower() == "gmail":
                        send_auto_reply(access_token, recipient_email, order_message, account_id, thread_id, original_message_id, subject)
                    elif account_type.lower() == "imap":
                        send_imap_reply(access_token, recipient_email, order_message, account_id, subject)
                    elif account_type.lower() == "outlook":
                        print(account_type,"ACCOunt TYpe")
                        send_outlook_reply(access_token, recipient_email, message, account_id, thread_id, message_id, subject)
                    else:
                        print(f"Unknown account type after order query: {account_type}")    
                

                if status != "success" and status != "action_required" and status != "error":
                    # Email.objects.filter(message_id=message_id).update(is_incident=True)
                    email = Email.objects.get(message_id=message_id)
                    email.is_incident = True
                    email.save()
            except json.JSONDecodeError:
                message = ai_response  
        except Exception as e:
            ai_response = "Dear Customer,\n\nWe couldn't generate a response at this time. Please try again later.\n\nBest regards,\nZenflows.ai"


# -------------------------------------------------------------------------------------------------------------

def handle_order_query(order_id, recipient_email, access_token, account_id, message_id):
    try:
        user_account = UserAccount.objects.get(id=account_id)
        user = user_account.user
        user_email = Users.objects.get(email=user)
    except UserAccount.DoesNotExist:
        user_account = UserAccount.objects.get(id=account_id)
        user = user_account.user
        user_email = Users.objects.get(email=user)
        print("User account not found with this email ID")
        Email.objects.filter(message_id=message_id).update(is_incident=True)
        createnotification(user_email, "User account not found with this email ID", "alert")
        return {"success": False, "error": "User account not found."}
    try:
        user_account = UserAccount.objects.get(id=account_id)
        user = user_account.user
        user_email = Users.objects.get(email=user)
        user_id = user_email.id
        shop = ShopifyStore.objects.get(user_id=user_id)
    except ShopifyStore.DoesNotExist:
        print("No Shopify store found for this user")
        user_account = UserAccount.objects.get(id=account_id)
        user = user_account.user
        user_email = Users.objects.get(email=user)
        user_id = user_email.id 
        createnotification(user_id, "No Shopify store found.", "alert")
        Email.objects.filter(message_id=message_id).update(is_incident=True)
        return {"success": False, "error": "No Shopify store found."}

    shop_url = shop.shop_domain
    shop_token = shop.access_token
    headers = {
        "X-Shopify-Access-Token": shop_token,
        "Content-Type": "application/json"
    }
    # Step 1: Fetch customer info by email
    search_customer_url = f"https://{shop_url}/admin/api/2023-10/customers/search.json?email={recipient_email}"
    customer_response = requests.get(search_customer_url, headers=headers)

    if customer_response.status_code != 200:
        user_account = UserAccount.objects.get(id=account_id)
        user = user_account.user
        user_email = Users.objects.get(email=user)
        user_id = user_email.id 
        Email.objects.filter(message_id=message_id).update(is_incident=True)
        createnotification(user_email, "Failed to fetch customer info. from the coustomer ID ", "alert")
        return {"success": False, "error": "Failed to fetch customer info."}

    customers = customer_response.json().get("customers", [])
    if not customers:
        user_account = UserAccount.objects.get(id=account_id)
        user = user_account.user
        user_email = Users.objects.get(email=user)
        user_id = user_email.id 
        
        Email.objects.filter(message_id=message_id).update(is_incident=True)
        createnotification(user_email,  f"No customers found with this email: {recipient_email}", "alert")
        return {"success": False, "error": "No customers found with this email."}

    last_order_id = customers[0].get("last_order_id")
    if not last_order_id:
        user_account = UserAccount.objects.get(id=account_id)
        user = user_account.user
        user_email = Users.objects.get(email=user)
        user_id = user_email.id
        Email.objects.filter(message_id=message_id).update(is_incident=True)
        createnotification(user_email, f"No recent orders found with this email: {recipient_email}", "alert")
        return {"success": False, "error": "No recent order found for this customer."}

    # Step 2: Fetch order details
    order_url = f"https://{shop_url}/admin/api/2023-10/orders/{last_order_id}.json"
    order_response = requests.get(order_url, headers=headers)

    if order_response.status_code != 200:
        user_account = UserAccount.objects.get(id=account_id)
        user = user_account.user
        user_email = Users.objects.get(email=user)
        user_id = user_email.id 
        Email.objects.filter(message_id=message_id).update(is_incident=True)
        createnotification(user_email, f"Failed to fetch orders with this email: {recipient_email}", "alert")
        return {"success": False, "error": "Failed to fetch order details."}

    order_data = order_response.json().get("order", {})
    order_status_url = order_data.get("order_status_url")

    if not order_status_url:
        return {
            "success": True,
            "order_status_url": None,
            "message": "Your order is being processed. Order tracking link is not available yet."
        }
    return {
        "success": True,
        "order_status_url": order_status_url,
        "message": f"You can check your order status here:\n{order_status_url}"
    }

   

def handle_order_not_found(recipient_email, access_token, account_id):
    message = (
        "Dear Customer,\n\n"
        "We couldn't find a valid order number in your message. Please double-check your tracking or order ID and try again.\n\n"
        "If you need help, don't hesitate to reach out 😊\n"
        "We're here to help you!\n\n"
        "Have a wonderful day ❤️\n"
        "\n"
        "Zenflows.ai Customer Support"
    )
    send_auto_reply(access_token, recipient_email, message, account_id)

# -------------------------------------------------------------------------------------------------------------

def send_auto_reply(access_token, recipient_email,message,account_id,thread_id,original_message_id,subject):
    """
    Sends an auto-reply email to the sender.
    """
    print("Auto-reply execution started after 10 seconds...",account_id)
    predefined_message = message
    try:
        user_account = UserAccount.objects.get(id=account_id)
        sender_email = user_account.email
    except UserAccount.DoesNotExist:
        print("Failed to fetch sender email.")
        return
    subject_line = f"Re: {subject}"
 
    # Encode the email content in base64
    raw_message =  f"From: {sender_email}\r\n" \
                    f"To: {recipient_email}\r\n" \
                    f"Subject: {subject_line}\r\n" \
                    f"In-Reply-To: {original_message_id}\r\n" \
                    f"References: {original_message_id}\r\n" \
                    f"Content-Type: text/plain; charset=\"UTF-8\"\r\n\r\n" \
                    f"{message}"
 
    encoded_message = base64.urlsafe_b64encode(raw_message.encode("utf-8")).decode("utf-8")
 
    url = "https://www.googleapis.com/gmail/v1/users/me/messages/send"
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
    }
    payload = {"raw": encoded_message,"threadId":thread_id}
    print("payload",payload)
    response = requests.post(url, json=payload, headers=headers)
    if response.status_code == 200:
        print(f"Auto-reply sent to {recipient_email}")
    
        # Save to SentEmail model
        try:
            print("saving the sent mail messages")
            user_account = UserAccount.objects.get(id=account_id)
            SentEmail.objects.create(        
                sender=sender_email,
                receiver=recipient_email,
                subject="Query Response",
                snippet=message,  # Store a short preview
                timestamp= timezone.now(),
                account=user_account,
                reply_type='ai'
            )
            print("Auto-reply saved in SentEmail model.")
            subscriptions = UserSubscription.objects.filter(user=user_account.user)
            print("subscriptions",subscriptions)
            for sub in subscriptions:
                # Check if this subscription is active and relevant
                    sub.email_count += 1
                    sub.save()
                    print(f"Email count updated to {sub.email_count} for subscription {sub.id}")
                    break 
        except UserAccount.DoesNotExist:
            print(f"UserAccount with ID {account_id} not found.")
        except UserAccount.DoesNotExist:
            print(f"UserAccount with ID {account_id} not found.")
    else:
        print(f"Failed to send auto-reply: {response.text}")

# # -------------------------------------------------------------------------------------------------------------
class SentEmailListView(APIView):
    def post(self, request):
        try:
            email = request.data.get("email")  # Get email from request body
            if not email:
                return Response(
                    {
                        "status": "error",
                        "message": "Email is required.",
                        "data": None
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )
            # Find the user account linked to this email
            user_account = UserAccount.objects.filter(email=email).first()
            if not user_account:
                return Response(
                    {
                        "status": "error",
                        "message": "No user found with this email.",
                        "data": None
                    },
                    status=status.HTTP_404_NOT_FOUND,
                )

            # Fetch sent emails for the user account
            sent_emails = SentEmail.objects.filter(account=user_account).order_by('-timestamp')
            sent_email_count = sent_emails.count()
            print("sent_email_count",sent_email_count)

            if sent_email_count == 0:
                return Response(
                    {
                        "status": "success",
                        "message": "No sent emails found for this user.",
                        "sent_email_count": 0,
                        "data": []
                    },
                    status=status.HTTP_200_OK,
                )

            serializer = SentEmailSerializer(sent_emails, many=True)

            return Response(
                {
                    "status": "success",
                    "message": "Sent emails retrieved successfully.",
                    "sent_email_count": sent_email_count,
                    "data": serializer.data,
                },
                status=status.HTTP_200_OK,
            )
        except Exception as e:
            return Response(
                {
                    "status": "error",
                    "message": "An error occurred while fetching sent emails.",
                    "error": str(e),
                    "data": None
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class EmailListView(APIView):
    def post(self, request):
        try:
            email = request.data.get("email")  # Get email from request body
            search_query = request.query_params.get("search", None)  # Get search query

            if not email:
                return Response(
                    {
                        "status": "error",
                        "code": 400,
                        "message": "Email is required.",
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )

            # Find the user account linked to this email
            user_account = UserAccount.objects.filter(email=email).first()
            if not user_account:
                return Response(
                    {
                        "status": "error",
                        "code": 404,
                        "message": "No user found with this email.",
                    },
                    status=status.HTTP_404_NOT_FOUND,
                )

            # Fetch emails for the user account
            emails = Email.objects.filter(account=user_account).order_by('-timestamp')
            # Count after filtering (with search, if applied)
            filtered_email_count = emails.count()
            # Total inbox emails for the user (before any filtering)
            total_inbox_count = Email.objects.filter(account=user_account).count()


            # Apply search filter (search by subject, sender, or snippet)
            if search_query:
                emails = emails.filter(
                    Q(subject__icontains=search_query) | 
                    Q(sender__icontains=search_query) | 
                    Q(snippet__icontains=search_query)
                )

            # Get total email count after filtering
            email_count = emails.count()

            # Check if there are any emails
            if email_count == 0:
                return Response(
                    {
                        "status": "success",
                        "code": 200,
                        "message": "No emails found for this user.",
                        "email_count": 0,
                        "data": []
                    },
                    status=status.HTTP_200_OK,
                )

            # Implement pagination
            paginator = PageNumberPagination()
            paginated_emails = paginator.paginate_queryset(emails, request)

            # Serialize paginated data
            serializer = EmailSerializer(paginated_emails, many=True)

            return paginator.get_paginated_response(
                {
                    "status": "success",
                    "code": 200,
                    "message": "Emails retrieved successfully.",
                    "email_count": filtered_email_count,
                    "total_inbox_count": total_inbox_count,
                    "data": serializer.data,
                }
            )
        except Exception as e:
            return Response(
                {
                    "status": "error",
                    "code": 500,
                    "message": "An error occurred while fetching emails.",
                    "error": str(e),
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )
class GetIncidentEmailsAPIView(APIView):
    def post(self, request):
        try:
            # Extract email from the request body
            email = request.data.get("email")
            if not email or not isinstance(email, str):
                return Response(
                    {
                        "status": "error",
                        "code": 400,
                        "message": "Invalid request. Provide a valid email address as a string."
                    },
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Fetch incident-related emails where `is_incident=True` and email is in recipients
            incident_emails = Email.objects.filter(
                is_incident=True
            ).filter(
                Q(recipients=email) | Q(recipients__icontains=email)
            ).distinct()

            # Get the count of incident emails
            email_count = incident_emails.count()

            if email_count == 0:
                return Response(
                    {
                        "status": "success",
                        "code": 200,
                        "message": "No incident emails found for the given email.",
                        "email_count": 0,
                        "data": []
                    },
                    status=status.HTTP_200_OK
                )

            # Serialize the data
            serializer = EmailSerializer(incident_emails, many=True)

            return Response(
                {
                    "status": "success",
                    "code": 200,
                    "message": "Incident emails retrieved successfully.",
                    "email_count": email_count,
                    "data": serializer.data
                },
                status=status.HTTP_200_OK
            )
        except Exception as e:
            return Response(
                {
                    "status": "error",
                    "code": 500,
                    "message": "An error occurred while fetching incident emails.",
                    "error": str(e)
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

 
# -------------------------------------------------------------------------------------------------------------
 
 

 
class EmailDetailsView(APIView):
    
    def post(self, request):
        try:
            # Extract email_id from request data
            email_id = request.data.get("email_id")

            if not email_id:
                return Response(
                    {
                        "status": "error",
                        "code": 400,
                        "message": "Email ID is required."
                    },
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Fetch the email from the database
            email = Email.objects.filter(id=email_id).first()

            if not email:
                return Response(
                    {
                        "status": "error",
                        "code": 404,
                        "message": "Email not found."
                    },
                    status=status.HTTP_404_NOT_FOUND
                )

            # Serialize the email data
            serializer = EmailSerializer(email)

            return Response(
                {
                    "status": "success",
                    "code": 200,
                    "message": "Email details fetched successfully.",
                    "data": serializer.data
                },
                status=status.HTTP_200_OK
            )

        except Exception as e:
            return Response(
                {
                    "status": "error",
                    "code": 500,
                    "message": "An error occurred while fetching email details.",
                    "error": str(e)
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
 
### -----------------------------------------------------------------------------------------------------------------------------------------------------
 

class GetIncidentEmailsAPIView(APIView):
    def post(self, request):
        try:
            # Extract email from the request body
            email = request.data.get("email")

            if not email or not isinstance(email, str):
                return Response(
                    {
                        "status": "error",
                        "code": 400,
                        "message": "Invalid request. Provide a valid email address as a string."
                    },
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Fetch incident-related emails where `is_incident=True`
            incident_emails = Email.objects.filter(is_incident=True).filter(
                recipients=email
            ) | Email.objects.filter(
                is_incident=True,
                recipients__icontains=email  # Checks if email exists in recipients field
            )

            # Get the count of incident emails
            email_count = incident_emails.distinct().count()

            if email_count == 0:
                return Response(
                    {
                        "status": "success",
                        "code": 200,
                        "message": "No incident emails found for the given email.",
                        "email_count": 0,
                        "data": []
                    },
                    status=status.HTTP_200_OK
                )
            # Serialize the data
            serializer = EmailSerializer(incident_emails.distinct(), many=True)

            return Response(
                {
                    "status": "success",
                    "code": 200,
                    "message": "Incident emails retrieved successfully.",
                    "email_count": email_count,
                    "data": serializer.data
                },
                status=status.HTTP_200_OK
            )

        except Exception as e:
            return Response(
                {
                    "status": "error",
                    "code": 500,
                    "message": "An error occurred while fetching incident emails.",
                    "error": str(e)
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


# -------------------------------------------------------------------------------------------------------------
class IncidentEmailDetailsView(APIView):
    """
    API to fetch details of a specific incident email.
    """
    def post(self, request):
        try:
            # Extract email_id from request data
            email_id = request.data.get("email_id")

            if not email_id:
                return Response(
                    {
                        "status": "error",
                        "code": 400,
                        "message": "Email ID is required."
                    },
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Fetch the incident email from the database
            email = Email.objects.filter(id=email_id, is_incident=True).first()

            if not email:
                return Response(
                    {
                        "status": "error",
                        "code": 404,
                        "message": "Incident email not found."
                    },
                    status=status.HTTP_404_NOT_FOUND
                )

            # Serialize the email data
            serializer = EmailSerializer(email)

            return Response(
                {
                    "status": "success",
                    "code": 200,
                    "message": "Incident email details fetched successfully.",
                    "data": serializer.data
                },
                status=status.HTTP_200_OK
            )

        except Exception as e:
            return Response(
                {
                    "status": "error",
                    "code": 500,
                    "message": "An error occurred while fetching incident email details.",
                    "error": str(e)
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
# -------------------------------------------------------------------------------------------------------------
 
class SentEmailDetailsView(APIView):
    
    def post(self, request):
        try:
            email_id = request.data.get("email_id")
            print("Email",email_id)
            if not email_id:
                return Response({"message": "Email ID is required."}, status=status.HTTP_400_BAD_REQUEST)
 
            email = SentEmail.objects.filter(id=email_id).first()
            if not email:
                return Response(
                    {"message": "Email not found."}, status=status.HTTP_404_NOT_FOUND
                )

            serializer = SentEmailSerializer(email)
            return Response({"message": "Email details fetched successfully.", "data": serializer.data}, status=status.HTTP_200_OK)
 
        except Exception as e:
            return Response({"message": "Error fetching email details.", "error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
 
 
#  ------------------------------------------------------------------------------------------------
 

class ReplyIncidentMailView(APIView):
    """
    API to send a manual reply to an incident email
    """
    def post(self, request):
        try:
    
            # Extract required data from request
            email_id = request.data.get("email_id")  # The incident email ID
          
            reply_message = request.data.get("message")  # The manual reply content
            user_email = request.data.get("user_email")  # The user's email who is sending the reply
            # Validation
            if not all([email_id, reply_message, user_email]):
                return Response(
                    {
                        "status": "error",
                        "message": "email_id, message, and user_email are required",
                        "data": None
                    },
                    status=status.HTTP_400_BAD_REQUEST
                )
 
            # Get the original incident email
            try:
                incident_email = Email.objects.get(id=email_id, is_incident=True)
                print(incident_email,"success")
            except Email.DoesNotExist:
                return Response(
                    {
                        "status": "error",
                        "message": "Incident email not found or not marked as incident",
                        "data": None
                    },
                    status=status.HTTP_404_NOT_FOUND
                )
 
            # Get the user account for sending the reply
            try:
                user_account = UserAccount.objects.get(email=user_email)
                user_account_email= user_account.email
                access_token = user_account.access_token
                account_type = user_account.account_type 
            except UserAccount.DoesNotExist:
                return Response(
                    {
                        "status": "error",
                        "message": "User account not found",
                        "data": None
                    },
                    status=status.HTTP_404_NOT_FOUND
                )
            if account_type == "imap":
                imap_response = send_imap_email_reply(user_account_email, incident_email, reply_message)
                return imap_response 
            elif account_type == "outlook":
                return send_incident_reply(email_id, user_email, reply_message)
 
            # Prepare email content
            recipient_email = incident_email.sender  # Reply to the original sender
            subject = f" {incident_email.subject}"  # Preserve original subject with "Re:"
 
            # Encode the email content in base64
            raw_message = (
                f"To: {recipient_email}\r\n"
                f"Subject: {subject}\r\n"
                f"Content-Type: text/html; charset='UTF-8'\r\n\r\n"
                f"{reply_message}"
            )
            encoded_message = base64.urlsafe_b64encode(raw_message.encode("utf-8")).decode("utf-8")
 
            # Send email via Gmail API
            url = "https://www.googleapis.com/gmail/v1/users/me/messages/send"
            headers = {
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json",
            }
            payload = {"raw": encoded_message}
            response = requests.post(url, json=payload, headers=headers)
            if response.status_code == 200:
                sent_email = SentEmail.objects.create(
                    sender="me",
                    receiver=recipient_email,
                    subject=subject,
                    snippet=reply_message[:100],  # Store first 100 chars as snippet
                    timestamp=timezone.now(),
                    account=user_account,
                    reply_type="manual",
                )

                incident_email.is_incident = False  # Mark as resolved if needed
                incident_email.save()
                Notification.objects.filter(
                    user=user_account.user,
                    read=False,
                    notification_type="incident",
                    message__icontains=incident_email.subject[:50],
                ).update(read=True)

                return Response(
                    {
                        "status": "success",
                        "message": "Manual reply sent successfully",
                        "data": {
                            "sent_email_id": sent_email.id,
                            "recipient": recipient_email,
                            "subject": subject,
                        },
                    },
                    status=status.HTTP_200_OK,
                )
            else:
                return Response(
                    {
                        "status": "error",
                        "message": "Failed to send reply",
                        "error": response.text,
                        "data": None,
                    },
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR,
                )

        except Exception as e:
            return Response(
                {
                    "status": "error",
                    "message": "An error occurred while sending the manual reply",
                    "error": str(e),
                    "data": None
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )



class EmailCountView(APIView):
    def post(self, request):
        try:
            user_id = request.data.get("user_id")
            print(user_id, "Email User Id")

            if not user_id:
                return Response({
                    "status": "error",
                    "code": 400,
                    "message": "User ID is required."
                }, status=status.HTTP_400_BAD_REQUEST)

            user_accounts = UserAccount.objects.filter(user_id=user_id,is_logged=True)
            if not user_accounts.exists():
                return Response({
                    "status": "error",
                    "code": 404,
                    "message": "No user accounts found with this user ID."
                }, status=status.HTTP_404_NOT_FOUND)

            accounts_data = list(user_accounts.values("id", "email"))
            accounts_added_by_user = user_accounts.count()

            total_inbox_emails = 0
            total_incident_emails = 0
            total_sent_emails = 0
            total_response_time = timedelta(0)
            total_replied_emails = 0

            for account in user_accounts:
                account_email = account.email

                inbox_count = Email.objects.filter(account=account).count()
                total_inbox_emails += inbox_count

                incident_count = Email.objects.filter(
                    is_incident=True
                ).filter(
                    Q(recipients=account_email) | Q(recipients__icontains=account_email)
                ).distinct().count()
                total_incident_emails += incident_count

                sent_emails = SentEmail.objects.filter(account=account)
                total_sent_emails += sent_emails.count()

                # Calculate response times
                for sent in sent_emails:
                    if sent.related_email and sent.related_email.timestamp:
                        response_time = sent.timestamp - sent.related_email.timestamp
                        total_response_time += response_time
                        total_replied_emails += 1

            ai_response_rate = (
                (total_incident_emails / total_inbox_emails) * 100
                if total_inbox_emails > 0 else 0
            )

            avg_response_time = (
                total_response_time / total_replied_emails
                if total_replied_emails > 0 else timedelta(0)
            )
           
            return Response({
                "status": "success",
                "code": 200,
                "message": "Email summary retrieved successfully.",
                "data": {
                    "accounts_added_by_user": accounts_added_by_user,
                    "total_inbox_emails": total_inbox_emails,
                    "total_incident_emails": total_incident_emails,
                    "total_sent_emails": total_sent_emails,
                    "accounts": accounts_data,
                    "ai_response_rate_percent": round(ai_response_rate, 2),
                    "average_response_time": str(avg_response_time)
                }
            }, status=status.HTTP_200_OK)

        except Exception as e:
            print("Error in EmailSummaryAPIView:", str(e))
            return Response({
                "status": "error",
                "code": 500,
                "message": "An error occurred while fetching email summary.",
                "error": str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
# -------------------------------------------------------------------------------------------------------------

class FetchSubscriptions(APIView):
    def get(self, request, user_id):
        print("user_id", user_id)
        if not user_id:
            return Response({
                "status": 400,
                "message": "user_id is required.",
                "data": []
            }, status=status.HTTP_400_BAD_REQUEST)

        try:
            user_subscriptions = UserSubscription.objects.filter(user_id=user_id)
            results = []

            for user_sub in user_subscriptions:
                email_countzz = user_sub.email_count

                email_limit = user_sub.email_limit
                print("email_limit", email_limit)

                results.append({
                    'user_email': user_sub.user.email,
                    'subscription_id': user_sub.subscription_id,
                    'product_id': user_sub.product_id,
                    'email_count': email_countzz,
                    'period_start': user_sub.started_at,
                    'period_end': user_sub.expires_at,
                    'email_limit': int(email_limit),
                })

            return Response({
                "status": 200,
                "message": "success",
                "data": results
            }, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({
                "status": 404,
                "message": f"user not found. {str(e)}",
                "data": []
            }, status=status.HTTP_404_NOT_FOUND)
        
class FetchUnreadNotificationsView(APIView):
    def post(self, request):
        user_id = request.data.get("user_id")
        if not user_id:
            return Response({"error": "user_id is required."}, status=400)

        try:
            user_account = Users.objects.get(id=user_id)
            print("user_account",user_account)
            user = user_account.id
            print("user",user)
            notifications = Notification.objects.filter(user=user, read=False).order_by('-created_at')
            serializer = NotificationSerializer(notifications, many=True)
            data = serializer.data
            return Response({"status": "success", "notifications":data}, status=status.HTTP_200_OK)
        except Exception as e:
            print("reer",e)
            return Response({"error": f"user not found.{e}"}, status=status.HTTP_404_NOT_FOUND)
        
# -------------------------------------------------------------------------------------------------------------

class MarkNotificationReadView(APIView):
    def post(self, request):
        notification_id = request.data.get("notification_id")
        if not notification_id:
            return Response({"error": "Notification ID required"}, status=400)

        try:
            notif = Notification.objects.get(id=notification_id)
            notif.read = True
            notif.save()
            return Response({"status": "success", "message": "Notification marked as read"})
        except Notification.DoesNotExist:
            return Response({"error": "Notification not found"}, status=404)
        
# -------------------------------------------------------------------------------------------------------------



class TotalIncomeAllUsersView(APIView):
    def get(self, request):
        try:
            # Total income from all user subscriptions
            total_income = UserSubscription.objects.aggregate(total=Sum('unit_amount'))['total'] or 0
            
            # Count of users excluding the superadmin
            client_count = Users.objects.filter(is_superuser=False).count()
            subscribed_clients_count = UserSubscription.objects.values('id').distinct().count()

            return Response({
                "status": 200,
                "message": "Total income and client count retrieved successfully.",
                "total_income": total_income,
                "client_count": client_count,
                "subscribed_clients_count": subscribed_clients_count
            }, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({
                "status": 400,
                "message": "An error occurred while retrieving data.",
                "error": str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
# -------------------------------------------------------------------------------------------------------------

class ForgotPasswordView(APIView):
    def post(self, request):
        email = request.data.get("email")
        if not email:
            return Response({
                "code": 400,
                "message": "Email is required.",
                "data": None
            })
        try:
            # Check if the email exists in the Users table
            user = Users.objects.get(email=email)

            # Generate a unique token
            reset_token = get_random_string(length=32)

            # Save the token to the user
            user.reset_token = reset_token
            user.save()

            # Generate the reset link
            reset_link = f"{settings.FRONTEND_URL}/reset-pass?token={reset_token}"

            # Send the reset link via email
            send_email(
                user_email=email,
                original_subject="Password Reset Request",
                custom_message=f"Click the link below to reset your password:\n\n{reset_link}"
            )

            return Response({
                "Status": 200,
                "message": "Password reset link has been sent to your email.",
                "data": {
                    "email": email,
                    "reset_link": reset_link  # Optional: Include for debugging purposes
                }
            })

        except Users.DoesNotExist:
            return Response({
                "Status": 404,
                "message": "No user found with this email.",
                "data": None
            })

        except Exception as e:
            return Response({
                "Status": 500,
                "message": "An unexpected error occurred.",
                "data": str(e)
            })
        


class ResetPasswordView(APIView):
    def post(self, request, token):
        new_password = request.data.get("new_password")
        confirm_password = request.data.get("confirm_password")

        if not new_password or not confirm_password:
            return Response({
                "Status": 400,
                "message": "Both new_password and confirm_password are required.",
                "data": None
            })
        if new_password != confirm_password:
            return Response({
                "Status": 400,
                "message": "Passwords do not match.",
                "data": None
            })
        try:
            # Find the user with the given reset token
            user = Users.objects.get(reset_token=token)


            # Update the user's password
            user.set_password(new_password)
            user.reset_token = None  # Clear the reset token
            user.save()

            return Response({
                "Status": 200,
                "message": "Password has been reset successfully.",
                "data": None
            })

        except Users.DoesNotExist:
            return Response({
                "Status": 404,
                "message": "Invalid or expired reset token.",
                "data": None
            })

        except Exception as e:
            return Response({
                "Status": 500,
                "message": "An unexpected error occurred.",
                "data": str(e)
        })



class ContactFormView(APIView):
    def post(self, request):
        fullName = request.data.get("fullName")
        email = request.data.get("email")  # from the form (sender)
        subject = request.data.get("subject")
        message = request.data.get("message")

        if not all([fullName, email, subject, message]):
            return Response({"error": "All fields are required."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            send_contact_mail(fullName, email, subject, message)
            return Response({"success": "Message sent successfully."}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        

def save_email_to_db(user_account, email_data,user_id):
    """
    Save Microsoft email message to DB.
    """
    try:
        message_id = email_data.get('id')
        subject = email_data.get('subject', '')
        snippet = email_data.get('bodyPreview', '')
        history_id = email_data.get('changeKey', '')
        sender = email_data.get('from', {}).get('emailAddress', {}).get('address', '')
        to_recipients = [
            r['emailAddress']['address'] for r in email_data.get('toRecipients', [])
        ]
        recipients = ", ".join(to_recipients)
        conversationId = email_data.get('conversationId', '')
        print("conversationId",conversationId)
 
        # Optional: Check if already saved
        if Email.objects.filter(message_id=message_id).exists():
            print(f"Email with message_id {message_id} already exists.")
            return Email.objects.get(message_id=message_id)  # Return the already saved object
 
        email = Email.objects.create(
            message_id=message_id,
            subject=subject,
            snippet=snippet,
            history_id=history_id,
            sender=sender,
            recipients=recipients,
            account=user_account,
        )
        
        print(f"Saved email: {email} for user {user_id}")
        
 
        # Extract additional info required for response
        access_token = user_account.access_token
        thread_id = email_data.get('conversationId', '')
        original_message_id = email_data.get('internetMessageId', '')
        print("aaaaaaa----------",user_id,sender,snippet,message_id,original_message_id,thread_id,subject)
        # Call AI response handler
        send_ai_response(
            user_id=user_id,
            access_token=access_token,
            recipient_email=sender,
            snippet=snippet,
            message_id=message_id,
            original_message_id=original_message_id,
            thread_id=thread_id,
            subject=subject
        )
 
        return email
 
    except Exception as e:
        print("Error saving email:", str(e))
        return None
    

class DeleteUserInfo(APIView):
    """
    API to delete user information.
    """
    def post(self, request):
        account_id = request.data.get("account_id")
        print("account_id", account_id)
        if not account_id:
            return Response({
                "status": "error",
                "code": 400,
                "message": "User ID is required."
            }, status=status.HTTP_400_BAD_REQUEST)
 
        try:
            user = UserAccount.objects.get(id=account_id)
            user.is_logged = False  # Mark user as logged out
            user.save()
            return Response({
                "status": "success",
                "code": 200,
                "message": "User information deleted successfully."
            }, status=status.HTTP_200_OK)
 
        except Users.DoesNotExist:
            return Response({
                "status": "error",
                "code": 404,
                "message": "User not found."
            }, status=status.HTTP_404_NOT_FOUND)
 
        except Exception as e:
            return Response({
                "status": "error",
                "code": 500,
                "message": f"An error occurred: {str(e)}"
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)