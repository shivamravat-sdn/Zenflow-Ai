from django.db import models
from django.contrib.auth import get_user_model

# Create your models here.
class BaseModel(models.Model):
    created_date = models.DateTimeField(auto_now_add=True)
    modified_date = models.DateTimeField(auto_now=True)
    is_active = models.BooleanField(default=True)
    is_deleted = models.BooleanField(default=False)
    class Meta:
        abstract = True

class FAQ(BaseModel):
    user = models.ForeignKey(get_user_model(), on_delete=models.CASCADE,null=True, blank=True)
    question = models.CharField(max_length=512)
    answer = models.TextField()

    def __str__(self):
        return self.question


class Incident(BaseModel):
    email_subject = models.CharField(max_length=512)
    email_body = models.TextField()
    resolved = models.BooleanField(default=False)
    
    def __str__(self):
        return self.email_subject

class Email(BaseModel):
    STATUS_CHOICES = [
        ("pending", "Pending"),
        ("responded", "Responded"),
        ("incident", "Incident"),
    ]

    sender = models.EmailField()
    subject = models.CharField(max_length=512)
    body = models.TextField()
    ai_generated_response = models.TextField(null=True, blank=True)
    confidence_score = models.FloatField(null=True, blank=True)
    status = models.CharField(max_length=50, choices=STATUS_CHOICES, default="pending")

    def __str__(self):
        return self.subject

class AIResponseLog(BaseModel):
    email = models.ForeignKey(Email, on_delete=models.CASCADE)
    ai_response = models.TextField()
    confidence_score = models.FloatField()
    response_time = models.FloatField()
    error_details = models.TextField(null=True, blank=True)

    def __str__(self):
        return f"Response for {self.email.subject}"
    
class APIIntegration(BaseModel):
    MAIL_CHOICES = [
        ("gmail", "Gmail"),
        ("outlook", "Outlook"),
    ]
    
    user = models.ForeignKey(get_user_model(), on_delete=models.CASCADE)
    service_name = models.CharField(max_length=50, choices=MAIL_CHOICES)
    api_key = models.CharField(max_length=255)
    is_connected = models.BooleanField(default=False)

    def __str__(self):
        return f"{self.user.email} - {self.service_name}"