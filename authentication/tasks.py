from celery import shared_task
from django.conf import settings
from authentication.models import UserAccount
import requests
import base64
from datetime import datetime
from celery import shared_task
from django.utils import timezone
from datetime import timedelta
from .models import UserAccount
from .utils import renew_gmail_watch_api
 
@shared_task
def send_auto_reply_task(access_token, recipient_email):
    """
    Sends an auto-reply email to the sender after a delay.
    """
    print("Scheduled auto-reply execution")
    predefined_message = "Hello, this is an automatic response. We will get back to you soon! backend test"
 
    # Encode the email content in base64
    raw_message = f"To: {recipient_email}\r\n" \
                  f"Subject: Re: Your Email\r\n" \
                  f"Content-Type: text/plain; charset='UTF-8'\r\n\r\n" \
                  f"{predefined_message}"
 
    encoded_message = base64.urlsafe_b64encode(raw_message.encode("utf-8")).decode("utf-8")
 
    url = "https://www.googleapis.com/gmail/v1/users/me/messages/send"
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
    }
    payload = {"raw": encoded_message}
 
    response = requests.post(url, json=payload, headers=headers)
 
    if response.status_code == 200:
        print(f"Auto-reply sent to {recipient_email}")
    else:
        print(f"Failed to send auto-reply: {response.text}")

        
@shared_task
def refresh_access_token():
    try:
        user_account = UserAccount.objects.filter(account_type='gmail')
        print("user_account",user_account)
        current_time = datetime.now()  
        token_url = "https://oauth2.googleapis.com/token"
        
    
        for user in user_account:
            if not user.refresh_token:
                continue
            if user.is_logged:
                # Get the current time
                last_login_naive = user.last_login.replace(tzinfo=None)  # Remove timezone info if it's there
                time_difference = current_time - last_login_naive
                minutes_difference = time_difference.total_seconds() / 60
                if minutes_difference>55:
                    print("Access token refreshed for user:", user.email)
                    data = {
                        "client_id": settings.GMAIL_CLIENT_ID,
                        "client_secret": settings.GMAIL_CLIENT_SECRET,
                        "refresh_token": user.refresh_token,
                        "grant_type": "refresh_token",
                    }
                    response = requests.post(token_url, data=data)
                    new_tokens = response.json()
                    if response.status_code != 200:
                        print("Failed to refresh token:", user.email)
                        continue
                   
                    user.access_token = new_tokens["access_token"]
                    user.last_login=current_time
                    user.save()
                    print("Access token refreshed for user:", user.email)
                else:
                    print("Token refresh not required for user:", user.email)
    except UserAccount.DoesNotExist:
        return {"error": "User not found"}   
    




@shared_task
def renew_watchers_for_all_users():
    now = timezone.now()
    threshold = now + timedelta(days=1)  # Renew if expiring in next 24 hours

    for account in UserAccount.objects.filter(is_logged=True,account_type='gmail'):
        # Condition: only renew if expiry is within 24 hours
        if account.subscription_expiration and account.subscription_expiration <= threshold:
            print(f"🔁 Renewing Gmail watcher for: 1 ----{account.email}")
            renew_gmail_watch_api(account)
