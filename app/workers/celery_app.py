from celery import Celery

from app.core.config import settings

celery_app = Celery(
    "ekyc",
    broker=settings.redis_url,
    backend=settings.redis_url,
    include=["app.workers.tasks"],
)

# Two worker pools: `gpu` for vision/model inference (OCR, liveness, face matching),
# `cpu` for everything else (hashing, PDF, signature, OTP, webhooks). The GPU pool is
# shared by all tenants and scales horizontally without touching the API or clients.
GPU_QUEUE = "gpu"
CPU_QUEUE = "cpu"

celery_app.conf.update(
    task_always_eager=settings.celery_always_eager,
    task_eager_propagates=False,
    task_acks_late=True,
    task_default_queue=CPU_QUEUE,
    task_routes={
        "ekyc.process_document": {"queue": GPU_QUEUE},
        "ekyc.process_selfie": {"queue": GPU_QUEUE},
        "ekyc.deliver_webhook": {"queue": CPU_QUEUE},
    },
    worker_prefetch_multiplier=1,
    broker_connection_retry_on_startup=True,
)
