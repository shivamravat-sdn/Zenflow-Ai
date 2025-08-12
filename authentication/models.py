

from django.db import models
from ai.models import BaseModel
from django.contrib.auth.models import AbstractUser
from django.utils import timezone

class Users(AbstractUser, BaseModel):
    email = models.EmailField(unique=True)
    reset_token = models.CharField(max_length=64, blank=True, null=True)  # Add this field
    trial_end_date = models.DateTimeField(null=True, blank=True)
    trial_email_count = models.IntegerField(default=0, null=True, blank=True)
    trial_email_limit = models.IntegerField(default=5, null=True, blank=True)
    
    def __str__(self):
        return self.email

class UserAccount(models.Model):
    ACCOUNT_TYPE_CHOICES = [
        ('gmail', 'Gmail'),
        ('outlook', 'Outlook'),
        ('IMAP', 'IMAP'),
    ]
 
    user = models.ForeignKey(Users, on_delete=models.CASCADE, related_name='accounts')
    account_type = models.CharField(max_length=10, choices=ACCOUNT_TYPE_CHOICES)
    email = models.EmailField(unique=True)
    access_token = models.TextField(blank=True, null=True)
    refresh_token = models.TextField(blank=True, null=True)
    history_id = models.CharField(max_length=255, blank=True, null=True)
    last_login = models.DateTimeField(blank=True, null=True)  # Stores last login timestamp
    is_logged = models.BooleanField(default=False)  # Indicates if the user is currently logged in
    imap_server = models.CharField(max_length=255, blank=True, null=True)  
    imap_port = models.IntegerField(blank=True, null=True)
    subscription_id = models.CharField(max_length=255, blank=True, null=True)
    subscription_expiration = models.DateTimeField(blank=True, null=True)  
    def __str__(self):
        return f"{self.user.email} - {self.account_type} - {self.email}"
    


class Email(models.Model):
    message_id = models.CharField(max_length=255, unique=True)
    subject = models.TextField()
    snippet = models.TextField()
    history_id = models.CharField(max_length=255)
    sender = models.CharField(max_length=255)      
    recipients = models.TextField()              
    timestamp = models.DateTimeField(auto_now_add=True)
    account = models.ForeignKey(UserAccount, on_delete=models.CASCADE, related_name='emails', blank=True, null=True)  # Foreign key to UserAccount
    is_incident = models.BooleanField(default=False) 

    def __str__(self):
        return self.subject

class SentEmail(models.Model):
    REPLY_TYPE_CHOICES = (
        ('manual', 'Manual'),
        ('ai', 'AI'),
    )
    sender = models.CharField(max_length=255)  # Sender's email
    receiver = models.TextField()  # Receiver's email
    subject = models.TextField()
    snippet = models.TextField()  # Short preview of the email content
    timestamp = models.DateTimeField(auto_now_add=True)
    account = models.ForeignKey(UserAccount, on_delete=models.CASCADE, related_name='sent_emails')
    related_email = models.ForeignKey(Email, on_delete=models.SET_NULL, null=True, blank=True, related_name='responses')
    reply_type = models.CharField(
        max_length=10,
        choices=REPLY_TYPE_CHOICES,
        default='ai'
    )

    def __str__(self):
        return f"Sent by {self.sender} to {self.receiver} - {self.subject}"


class Notification(models.Model):
    NOTIFICATION_TYPES = (
        ('message', 'Message'),
        ('alert', 'Alert'),
        ('system', 'System'),
        ('incident', 'Incident'),

    )
    user = models.ForeignKey(Users, on_delete=models.CASCADE,related_name='notifications')
    message = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    read = models.BooleanField(default=False)
    notification_type = models.CharField(max_length=50, choices=NOTIFICATION_TYPES, default='incident')