# signals.py
from django.db.models.signals import post_save,pre_save
from django.dispatch import receiver
from .models import *
from subscriptions.models import UserSubscription

@receiver(post_save, sender=Email)
def create_incident_email_notification(sender, instance, created, **kwargs):
    print("Creating notification for incident email 1")
    if instance.is_incident and instance.account: 
        print("Creating notification for incident email 3")
        user = instance.account.user
        Notification.objects.create(
            user=user,
            message=f"Unread Message From {instance.sender}: {instance.subject[:100]}",
            notification_type="incident"
        )
        


@receiver(pre_save, sender=UserSubscription)
def check_user_subscription_email_usage(sender, instance, **kwargs):
    try:
        previous = UserSubscription.objects.get(pk=instance.pk)
        prev_count = previous.email_count
        prev_limit = previous.email_limit
    except UserSubscription.DoesNotExist:
        # New object, skip notification
        return

    new_count = instance.email_count
    new_limit = instance.email_limit

    if new_limit == 0:
        return

    previous_percentage = (prev_count / new_limit) * 100
    current_percentage = (new_count / new_limit) * 100

    # Trigger only when crossing the 80% mark
    if previous_percentage < 80 <= current_percentage:
        Notification.objects.create(
            user=instance.user,
            message=f"Your email usage for the subscription '{instance.name}' has reached {current_percentage:.2f}% of your limit.",
            notification_type="alert"
        )