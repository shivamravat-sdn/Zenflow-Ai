# Zenflow Backend

This is the backend for the Zenflow project, built with Django, Django REST Framework, Celery, and Docker. It provides APIs for AI-powered email responses, authentication, subscription management, and integrations with external services like Shopify, Outlook, and IMAP.

## Features

- User authentication and management
- AI-powered email response generation
- Background task processing with Celery and Redis
- API monitoring with Prometheus
- Dockerized for easy deployment

## Project Structure

```
Zenflow-backend/
├── ai/                # AI-powered features and endpoints
├── authentication/    # User authentication and related logic
├── subscriptions/     # Subscription management
├── shopify/           # Shopify integration
├── imap/              # IMAP email integration
├── outlook/           # Outlook integration
├── ZenflowAi/         # Project settings, URLs, Celery config
├── Dockerfile
├── docker-compose.yml
├── manage.py
├── requirements.txt
└── README.md
```

## Getting Started

### Prerequisites

- Docker & Docker Compose
- Python 3.10+ (for local development)
- PostgreSQL (used as the database)
- Redis (used as the Celery broker)

### Environment Variables

Copy and configure your environment variables in `env/.env.staging`. See [`ZenflowAi/settings.py`](ZenflowAi/settings.py) for required variables.

### Build and Run with Docker

```sh
docker-compose up --build
```

- The Django app will be available at `http://localhost:9096/`
- Celery worker and beat will run in the background
- Redis will be used as the message broker

### Running Migrations

Migrations are run automatically on container startup. To run manually:

```sh
docker-compose exec web python manage.py makemigrations
docker-compose exec web python manage.py migrate
```

### Running Tests

```sh
docker-compose exec web python manage.py test
```

## API Endpoints

- Main API: `/ai/`, `/auth/`, `/subscriptions/`, `/shopify/`, `/outlook/`, `/imap/`
- Admin: `/admin/`

See each app's `urls.py` for details.

## Celery Tasks

Celery is configured in [`ZenflowAi/celery.py`](ZenflowAi/celery.py). Periodic tasks are managed with `django_celery_beat`.

## License

[MIT](LICENSE) (add your license file if needed)

---

For more details, see the source code and comments in each module.