import base64
import requests
from googleapiclient.errors import HttpError
from email.mime.text import MIMEText

from google.auth.exceptions import RefreshError
# from .mail_auth import authenticate_gmail, authenticate_outlook


import base64
from email.mime.text import MIMEText
from googleapiclient.discovery import build
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
import base64
from email.mime.text import MIMEText
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from google.oauth2.credentials import Credentials

# def send_gmail(access_token, refresh_token, client_id, client_secret, subject, body, to):
#     creds = Credentials(
#         token=access_token,
#         refresh_token=refresh_token,
#         token_uri='https://oauth2.googleapis.com/token',
#         client_id=client_id,
#         client_secret=client_secret
#     )
#     service = build('gmail', 'v1', credentials=creds)
#     message = MIMEText(body)
#     message['to'] = to
#     message['subject'] = subject
#     raw = base64.urlsafe_b64encode(message.as_bytes()).decode()
#     message = {'raw': raw}
#     try:
#         sentmessage = service.users().messages().send(userId='me', body=message).execute()
#         return sentmessage
#     except HttpError as error:
#         print(f'An error occurred: {error}')
#         return None

# def send_gmail(access_token, refresh_token, client_id, client_secret, subject, body, to):
#     print("Access Token:", access_token)
#     print("Refresh Token:", refresh_token)
#     print("Client ID:", client_id)
#     print("Client Secret:", client_secret)
#     creds = Credentials(
#         token=access_token,
#         refresh_token=refresh_token,
#         token_uri='https://oauth2.googleapis.com/token',
#         client_id=client_id,
#         client_secret=client_secret
#     )

#     # Attempt to refresh the token if expired
#     if creds.expired and creds.refresh_token:
#         try:
#             creds.refresh(Request())
#         except Exception as e:
#             print(f'Token refresh error: {e}')
#             return None

#     service = build('gmail', 'v1', credentials=creds)
#     message = MIMEText(body)
#     message['to'] = to
#     message['subject'] = subject
#     raw = base64.urlsafe_b64encode(message.as_bytes()).decode()
#     message = {'raw': raw}

#     try:
#         sent_message = service.users().messages().send(userId='me', body=message).execute()
#         return sent_message
#     except HttpError as error:
#         print(f'An error occurred: {error}')
#         return None

def send_gmail(access_token, subject, body, to):
    creds = Credentials(token=access_token)
    service = build('gmail', 'v1', credentials=creds)
    message = MIMEText(body)
    message['to'] = to
    message['subject'] = subject
    raw = base64.urlsafe_b64encode(message.as_bytes()).decode()
    message = {'raw': raw}
    try:
        sentmessage = service.users().messages().send(userId='me', body=message).execute()
        return sentmessage
    except HttpError as error:
        print(f'An error occurred: {error}')
        return None
    
def get_gmail_messages(user, client_id, client_secret):
    """Fetch the user's latest Gmail messages using Gmail API"""
    
    if not user.gmail_refresh_token:
        return {"error": "No Gmail refresh token found"}

    # Exchange refresh token for a new access token
    token_url = "https://oauth2.googleapis.com/token"
    data = {
        "client_id": client_id,
        "client_secret": client_secret,
        "refresh_token": user.gmail_refresh_token,
        "grant_type": "refresh_token",
    }

    response = requests.post(token_url, data=data)
    token_data = response.json()

    if "access_token" not in token_data:
        return {"error": "Failed to refresh access token"}

    access_token = token_data["access_token"]

    # Call Gmail API to get messages
    gmail_api_url = "https://www.googleapis.com/gmail/v1/users/me/messages"
    headers = {"Authorization": f"Bearer {access_token}"}

    gmail_response = requests.get(gmail_api_url, headers=headers)
    
    if gmail_response.status_code != 200:
        return {"error": "Failed to fetch Gmail messages", "details": gmail_response.json()}

    return {"messages": gmail_response.json()}
    

# def send_outlook_email(user, subject, body, to):
#     access_token = authenticate_outlook(user)
#     headers = {
#         'Authorization': f'Bearer {access_token}',
#         'Content-Type': 'application/json'
#     }
#     email_msg = {
#         'Message': {
#             'Subject': subject,
#             'Body': {
#                 'ContentType': 'Text',
#                 'Content': body
#             },
#             'ToRecipients': [
#                 {
#                     'EmailAddress': {
#                         'Address': to
#                     }
#                 }
#             ]
#         },
#         'SaveToSentItems': 'true'
#     }
#     response = requests.post(
#         'https://graph.microsoft.com/v1.0/me/sendMail',
#         headers=headers,
#         json=email_msg
#     )
#     return response.status_code

# def get_outlook_messages(user):
#     access_token = authenticate_outlook(user)
#     headers = {
#         'Authorization': f'Bearer {access_token}'
#     }
#     response = requests.get(
#         'https://graph.microsoft.com/v1.0/me/messages',
#         headers=headers
#     )
#     return response.json()
