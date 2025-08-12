from pathlib import Path
from decouple import Config, RepositoryEnv
import os
from datetime import timedelta


# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent

env_file = os.path.join(BASE_DIR, "env",".env.staging")

config = Config(RepositoryEnv(env_file))
STATIC_URL = 'static/'
# STATIC_ROOT = os.path.join(BASE_DIR, "static")

STATICFILES_DIRS = [
    os.path.join(BASE_DIR, 'static'),
]

# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/5.1/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!  
SECRET_KEY = config("SECRET_KEY")


DEBUG = config("DEBUG", default=False, cast=bool)
ALLOWED_HOSTS = ["*"]

# ALLOWED_HOSTS = ['sdeiaiml.com']
# USE_X_FORWARDED_HOST = True




PINECONE_API_KEY = config('api_key')
OPENAI_API_KEY = config('openai.api_key')
PINECONE_ENV=config('PINECONE_ENV')


# Application definition

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "corsheaders",
    "rest_framework",
    "rest_framework_simplejwt",
    "ai",
    "authentication",
    "subscriptions",
    "django_celery_beat",
    "django_prometheus",
    "shopify",
    "imap",
    "outlook",
]

MIDDLEWARE = [
    "corsheaders.middleware.CorsMiddleware",
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware"
]

ROOT_URLCONF = "ZenflowAi.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": ["templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "ZenflowAi.wsgi.application"


# Database
# https://docs.djangoproject.com/en/5.1/ref/settings/#databases

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": config("POSTGRES_NAME"),
        "USER": config("POSTGRES_USER"),
        "PASSWORD": config("POSTGRES_PASSWORD"),
        "HOST": config("POSTGRES_HOST"),
        "PORT": config("POSTGRES_PORT"),
    }
}

CORS_ALLOW_ALL_ORIGINS = True

# CORS_ALLOWED_ORIGINS = [
#     "http://localhost:3001",
#     "http://localhost:3000",
#     "https://sdeiaiml.com:9047",
#     "http://54.185.127.165:9046"
# ]
CORS_ALLOW_HEADERS = [
    "content-type",
    "authorization",
    "accept",
    "x-csrf-token",
    "x-requested-with",
]
CORS_ALLOW_METHODS = [
    "GET",
    "POST",
    "PUT",
    "PATCH",
    "DELETE",
    "OPTIONS",
]
CORS_ALLOW_CREDENTIALS = True

# Password validation
# https://docs.djangoproject.com/en/5.1/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        "NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.CommonPasswordValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.NumericPasswordValidator",
    },
]

AUTHENTICATION_BACKENDS = [
    'authentication.backends.EmailBackend',
    'django.contrib.auth.backends.ModelBackend',
]


REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": (
        "rest_framework_simplejwt.authentication.JWTAuthentication",
    ),
    "DEFAULT_PAGINATION_CLASS": "rest_framework.pagination.PageNumberPagination",
    "PAGE_SIZE": 10,  
}

SIMPLE_JWT = {
    "ACCESS_TOKEN_LIFETIME": timedelta(days=1),
    "REFRESH_TOKEN_LIFETIME": timedelta(days=1),
}

# Internationalization
# https://docs.djangoproject.com/en/5.1/topics/i18n/

LANGUAGE_CODE = "en-us"

TIME_ZONE = "UTC"

USE_I18N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/5.1/howto/static-files/

STATIC_URL = "static/"

# STATIC_ROOT = os.path.join(BASE_DIR, "static")

# Configure the media URL and root
MEDIA_URL = "/media/"  # URL to access media files
MEDIA_ROOT = os.path.join(BASE_DIR, "media")  # Root directory for media files

# Default primary key field type
# https://docs.djangoproject.com/en/5.1/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# Email Configuration for Gmail
EMAIL_BACKEND = config("EMAIL_BACKEND")
EMAIL_HOST = config("EMAIL_HOST")
EMAIL_PORT = config("EMAIL_PORT")
EMAIL_USE_TLS = config("EMAIL_USE_TLS")
EMAIL_HOST_USER = config("EMAIL_HOST_USER")
EMAIL_HOST_PASSWORD = config("EMAIL_HOST_PASSWORD")


AUTH_USER_MODEL = "authentication.Users"
FRONTEND_URL = config("FRONTEND_URL")

# Gmail and Outlook API credentials
GMAIL_CLIENT_ID = config('GMAIL_CLIENT_ID')
GMAIL_CLIENT_SECRET = config('GMAIL_CLIENT_SECRET')
OUTLOOK_CLIENT_ID = config('OUTLOOK_CLIENT_ID')
OUTLOOK_CLIENT_SECRET = config('OUTLOOK_CLIENT_SECRET')
GMAIL_REDIRECT_URIS = config('GMAIL_REDIRECT_URIS')
USE_X_FORWARDED_HOST = True
SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')


### celery config
CELERY_BROKER_URL = "redis://redis:6379/1"
CELERY_RESULT_BACKEND = "redis://redis:6379/2"
CELERY_ACCEPT_CONTENT = ["json"]
CELERY_TASK_SERIALIZER = "json"
CELERY_RESULT_SERIALIZER = "json"
CELERY_TIMEZONE = TIME_ZONE

# Stripe API keys
STRIPE_SECRET_KEY=config("STRIPE_SECRET_KEY")
STRIPE_PUBLISHABLE_KEY=config("STRIPE_PUBLISHABLE_KEY")
WEBHOOK_SECRET=config("WEBHOOK_SECRET")
WEBSITE_URL = config("WEBSITE_URL")
# Add this line to load the FRONTEND_URL from the environment
# FRONTEND_URL = config("FRONTEND_URL", default="http://localhost:3000/email-inbox")


SHOPIFY_STORE = config("SHOPIFY_STORE")
SHOPIFY_ACCESS_TOKEN = config("SHOPIFY_ACCESS_TOKEN")  



REDIRECT_URL = config("REDIRECT_URL")
SUCCESS_URL = config("SUCCESS_URL")
CANCEL_URL = config("CANCEL_URL")


CONTACT_RECEIVER_EMAIL = config("CONTACT_RECEIVER_EMAIL")



SHOPIFY_API_KEY = config("SHOPIFY_API_KEY")
SHOPIFY_API_SECRET = config("SHOPIFY_API_SECRET")
SHOPIFY_REDIRECT_URI = config("SHOPIFY_REDIRECT_URI")
SHOPIFY_FRONTEND_URL = config("SHOPIFY_FRONTEND_URL")

SHOPIFY_WEBHOOK_BASE_URL = config("SHOPIFY_WEBHOOK_BASE_URL")

MICROSOFT = {
    "CLIENT_ID": config("MICROSOFT_CLIENT_ID"),
    "CLIENT_SECRET_VALUE": config("MICROSOFT_CLIENT_SECRET"),
    "REDIRECT_URI": config("MICROSOFT_REDIRECT_URI"),
    "AUTHORITY": config("MICROSOFT_AUTHORITY"),
    "SCOPE": config("MICROSOFT_SCOPE"),
    "NOTIFICATION_URL": config("MICROSOFT_NOTIFICATION_URL"),
}
 