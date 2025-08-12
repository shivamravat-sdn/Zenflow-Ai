from django.urls import path
from .views import *

urlpatterns = [
    # User authentication and registration
    path('register/', UserRegistrationView.as_view(), name='user_registration'),
    path('clients/', ClientListView.as_view(), name='client-list'),
    path('clients/<int:user_id>/', ClientDetailView.as_view(), name='client-detail'),
    path('clients/', UserListView.as_view(), name='client_list'),
    path('client/register', ClientRegister.as_view(), name='client_list'),
 
    path('login/', UserLoginView.as_view(), name='login'),
    path('update/<int:pk>/', UserUpdateView.as_view(), name='update_user'),
    path('forgot-password/', ForgotPasswordView.as_view(), name='forgot_password'),
    path('reset-password/<str:token>/', ResetPasswordView.as_view(), name='reset_password'),

    # Google authentication
    path("initiate/", GoogleAuthView.as_view(), name="google_auth_initiate"),
    path("oauth2callback/", GoogleLoginCallbackView.as_view(), name="google_auth_callback"),
    
    # User information
    path("get_user_info/<int:id>", GetUserInfo.as_view(), name="get_user_info"),
    path("delete_user_info/", DeleteUserInfo.as_view(), name="delete_user_info"),
    
    # Gmail token and webhook
    path("get-gmail-token/<str:token>/", GetTokenView.as_view(), name="get_gmail_token"),
    path("webhook/", webhook, name="gmail_webhook"),
    path("set_gmail_watch/", setup_gmail_watch_api, name="set_gmail_watch"),
    
    # Email management
    path('emails/', EmailListView.as_view(), name='email_list'),
    path('email/details/', EmailDetailsView.as_view(), name="email_details"),
    
    # Sent emails
    path("sent-emails/", SentEmailListView.as_view(), name="sent_emails"),
    path('sent-emails/details/', SentEmailDetailsView.as_view(), name="sent_email_details"),
    
    # Token refresh
    path("refresh-token/", RefreshTokenView.as_view(), name="refresh_token"),
    
    # Incident-related emails
    path('incident/mails/', GetIncidentEmailsAPIView.as_view(), name="incident_emails"),
    path('incident/details/', IncidentEmailDetailsView.as_view(), name="incident_emails"),
    path('reply-incident-mail/', ReplyIncidentMailView.as_view(), name="reply_incident_mail"),

    # count 
    path('email-counts/', EmailCountView.as_view(), name="reply_incident_mail"),
    
    path('email-subs/<int:user_id>', FetchSubscriptions.as_view(), name="reply_incident_mail"),

    # path('create-notification/', CreateNotificationAPIView.as_view(), name="CreateNotificationAPIView"),
    path('fetch-unread-notifications/', FetchUnreadNotificationsView.as_view(), name="reply_incident_mail"),
    path('mark-notification-read/', MarkNotificationReadView.as_view(), name="reply_incident_mail"),

    ## # Subscription-related URLs
    path('totalincome/', TotalIncomeAllUsersView.as_view(), name='total_income_all_users'),
    # test email api 
    # path("test-email/<int:id>", test_email, name="test_email"),
    path("contact-us/", ContactFormView.as_view(), name="contact-us"),
]
