"""
Celery application — async worker configuration.

Broker: Redis (REDIS_URL env var)
Backend: Redis (same instance, separate DB)

Worker startup:
    celery -A workers.celery_app worker --loglevel=info --concurrency=4

Beat scheduler (for periodic scans):
    celery -A workers.celery_app beat --loglevel=info

In production, use separate Redis instances for broker and backend,
and run beat on a single instance to avoid duplicate scheduled tasks.
"""
import os
from celery import Celery
from celery.schedules import crontab
from kombu import Queue

REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
REDIS_BACKEND_URL = os.environ.get("REDIS_BACKEND_URL", "redis://localhost:6379/1")

app = Celery(
    "cloud_guardian",
    broker=REDIS_URL,
    backend=REDIS_BACKEND_URL,
    include=["workers.tasks"],
)

app.conf.update(

    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,


    task_acks_late=True,
    task_reject_on_worker_lost=True,
    worker_prefetch_multiplier=1,


    result_expires=3600,


    task_queues=[
        Queue("scans",       routing_key="scans.#"),
        Queue("remediations", routing_key="remediations.#"),
        Queue("default",     routing_key="default.#"),
    ],
    task_default_queue="default",
    task_routes={
        "workers.tasks.run_account_scan":        {"queue": "scans"},
        "workers.tasks.run_org_full_scan":       {"queue": "scans"},
        "workers.tasks.execute_remediation":     {"queue": "remediations"},
        "workers.tasks.retrain_anomaly_model":   {"queue": "scans"},
    },


    beat_schedule={

        "scan-all-accounts-15min": {
            "task": "workers.tasks.run_all_accounts_scan",
            "schedule": crontab(minute="*/15"),
            "options": {"queue": "scans"},
        },

        "retrain-models-daily": {
            "task": "workers.tasks.retrain_all_models",
            "schedule": crontab(hour=2, minute=0),
            "options": {"queue": "scans"},
        },
    },
)
