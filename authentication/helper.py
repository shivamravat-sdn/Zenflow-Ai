import base64
from django.core.mail import send_mail
from django.conf import settings
from authentication.models import Notification
from django.core.mail import EmailMultiAlternatives
from django.conf import settings


from django.conf import settings
def encode_email(
    sender, recipient_email, subject, body, in_reply_to=None, references=None
):
    email_template = f"""From: {sender}
                    To: {recipient_email}
                    Subject: {subject}"""

    if in_reply_to:
        email_template += f"\nIn-Reply-To: <{in_reply_to}>"

    if references:
        email_template += f"\nReferences: <{references}>"

    email_template += f"""
        Content-Type: text/plain; charset="UTF-8"
        {body}
"""
    # Encode in base64
    encoded_message = base64.urlsafe_b64encode(email_template.encode("utf-8")).decode(
        "utf-8"
    )
    return encoded_message



def send_email(user_email, original_subject, custom_message):
    text_message = (
        f"Hello,\n\n"
        f"{custom_message}\n\n"
        f"Best regards,\n"
        f"Zenflows Team"
    )

    # Convert plain text to styled HTML paragraphs
    html_custom_message = "<p>" + custom_message.replace("\n", "</p><p>") + "</p>"

    html_message = f"""
<html>
  <body style="font-family: Arial, sans-serif; background-color: #f4f4f4; padding: 20px;">
    <center>
      <!-- Header -->
      <table width="600" cellpadding="0" cellspacing="0" style="background-color: #ffffff; padding: 20px; border-radius: 8px;">
        <tr>
          <td align="center">
            <h2 style="color: #007BFF; margin: 0;">Welcome to Zenflows</h2>
          </td>
        </tr>
      </table>
      <!-- Main Message -->
      <table width="600" cellpadding="0" cellspacing="0" style="background-color: #ffffff; padding: 20px; border-radius: 8px; margin-top: 15px;">
        <tr>
          <td style="color: #333333; font-size: 15px; line-height: 1.6;">
            {html_custom_message}
          </td>
        </tr>
      </table>
 
      <!-- Footer -->
      <table width="600" cellpadding="0" cellspacing="0" style="background-color: #ffffff; padding: 20px; border-radius: 8px; margin-top: 20px;">
        <tr>
          <td valign="top" style="padding-left: 15px; font-size: 14px; color: #555555;">
            <strong style="color: #007BFF;">Zenflows Team</strong><br />
            📧 <a href="mailto:support@zenflows.ai" style="color: #007BFF;">support@zenflows.ai</a><br />
            🌐 <a href="https://zenflows.ai" style="color: #007BFF;">https://zenflows.ai</a>
          </td>
        </tr>
      </table>
 
      <p style="color: #aaa; font-size: 12px; margin-top: 30px;">You’re receiving this email because you’re a registered user of Zenflows.</p>
    </center>
  </body>
</html>
"""
    email = EmailMultiAlternatives(
        subject=original_subject,
        body=text_message,
        from_email=settings.EMAIL_HOST_USER,
        to=[user_email],
    )
    print("aaaa")
    email.attach_alternative(html_message, "text/html")
    try:
      email.send()
      print("mail sent done")
    except Exception as e:
      print("Failed to send email:", str(e))



def send_contact_mail(fullName, sender_email, subject, message):
    full_message = f"From: {fullName} <{sender_email}>\n\nMessage:\n{message}"
    send_mail(
        subject=subject,
        message=full_message,
        from_email=sender_email,  # sender (comes from form)
        recipient_list=[settings.CONTACT_RECEIVER_EMAIL],  # receiver (from settings)
        fail_silently=False,
    )



def createnotification(user,message,notification_type):
    try:
        Notification.objects.create(
            user=user,
            message=message,
            notification_type=notification_type
        )
        print("Notification created successfully.")
    except Exception as e:
        print(f"Error creating notification: {e}")

