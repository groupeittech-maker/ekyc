from celery import Celery

from app.core.config import settings

celery_app = Celery(
    "ekyc",
    broker=settings.redis_url,
    backend=settings.redis_url,
    include=["app.workers.tasks"],
)

celery_app.conf.update(
    task_always_eager=settings.celery_always_eager,
    task_eager_propagates=False,
    task_acks_late=True,
    task_default_queue="ekyc",
    task_routes={
        "ekyc.process_document": {"queue": "ocr"},
        "ekyc.process_selfie": {"queue": "biometrics"},
        "ekyc.deliver_webhook": {"queue": "webhooks"},
    },
    worker_prefetch_multiplier=1,
    broker_connection_retry_on_startup=True,
)
