import os

bind = os.environ.get("SR_BIND", "unix:/run/api/api.sock")
workers = 1
worker_class = "uvicorn.workers.UvicornWorker"
# Must exceed SR_EXTRACT_TIMEOUT_SECONDS (default 300) so long extractions survive.
timeout = int(os.environ.get("SR_GUNICORN_TIMEOUT", "330"))
graceful_timeout = int(os.environ.get("SR_GUNICORN_GRACEFUL_TIMEOUT", "30"))
loglevel = os.environ.get("SR_LOG_LEVEL", "info").lower()
accesslog = None
