from celery import Celery
from app.config import settings

celery_app = Celery(
    "sast_worker",
    broker=settings.CELERY_BROKER_URL,
    backend=settings.CELERY_RESULT_BACKEND,
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_time_limit=1800,
    task_soft_time_limit=1500,
    worker_max_tasks_per_child=50,
)

# Explicit task module imports for autodiscovery
celery_app.autodiscover_tasks(
    [
        "app.tasks.scan_tasks",
        "app.tasks.report_tasks",
        "app.tasks.github_tasks",
    ]
)
