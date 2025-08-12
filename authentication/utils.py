from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
import requests
from .models import UserAccount  # path change if needed

from datetime import datetime
GMAIL_WATCH_URL = "https://www.googleapis.com/gmail/v1/users/me/watch"

@csrf_exempt
def renew_gmail_watch_api(request):
    """Renews Gmail Watch for all users with valid access tokens."""
    try:
        print("🔁 Renewing Gmail Watch for all logged-in users...")

        users = UserAccount.objects.filter(is_logged=True, account_type='gmail')

        if not users.exists():
            return JsonResponse({"message": "No active users found."}, status=200)

        success_count = 0
        failure_count = 0
        errors = []

        for user in users:
            access_token = user.access_token
            print(f"🔁 Renewing watch for {user.email}...")

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

            if response.status_code == 200:
                data = response.json()
                history_id = data.get("historyId")
                expiration = data.get("expiration")  # milliseconds

                if history_id:
                    user.history_id = history_id

                if expiration:
                    expiration_dt = datetime.fromtimestamp(int(expiration) / 1000)
                    user.subscription_expiration = expiration_dt

                user.save(update_fields=["history_id", "subscription_expiration"])
                print(f" Watch renewed for {user.email} (History ID: {history_id})")
                success_count += 1
            else:
                print(f"Failed to renew for {user.email}: {response.text}")
                failure_count += 1
                errors.append({user.email: response.text})

        return JsonResponse({
            "message": "Watch renewal completed.",
            "success_count": success_count,
            "failure_count": failure_count,
            "errors": errors,
        }, status=200)

    except Exception as e:
        print("Error during Gmail watch renewal:", str(e))
        return JsonResponse({"error": str(e)}, status=500)
