import os
from celery import Celery
from celery.schedules import crontab
from django.conf import  settings
from datetime import timedelta


# Set default Django settings module for 'celery'
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "ZenflowAi.settings")

app = Celery("ZenflowAi")
# Using Redis as the broker and result backend
app.conf.update(
    broker_url=settings.CELERY_BROKER_URL,
    result_backend=settings.CELERY_RESULT_BACKEND,
    accept_content=['json'],  # Accept only JSON serialized tasks
    task_serializer='json',  # Serialize tasks as JSON
    result_serializer='json',  # Serialize results as JSON
    timezone=settings.TIME_ZONE,  # Default timezone
    enable_utc=True,  # Enable UTC timezone
)

# Load task modules from all registered Django app configs.
app.config_from_object("django.conf:settings", namespace="CELERY")

# Autodiscover tasks from all installed apps
app.autodiscover_tasks()

@app.task(bind=True)
def debug_task(self):
    print(f"Request: {self.request!r}")



app.conf.beat_schedule = {
    # 'check_refresh_token_every_10_min': {
    #     'task': 'authentication.tasks.refresh_access_token',
    #     'schedule': crontab(minute='*/10'),
    # },
    #  'check_Fetch_mails_from_IMAP_every_min': {
    #     'task': 'imap.tasks.fetch_all_imap_emails',
    #      'schedule': timedelta(seconds=10),  
    # },
    #     'refresh_outlook_token_every_10_min': {  
    #     'task': 'outlook.tasks.refresh_access_token_outlook',
    #     'schedule': crontab(minute='*/10'),
    # },
     'renew_gmail_watch_every_6_hours': {
        'task': 'authentication.tasks.renew_watchers_for_all_users',
        'schedule': timedelta(seconds=10),
    },
}