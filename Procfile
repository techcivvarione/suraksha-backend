web: alembic upgrade head && uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8080}
worker: python worker.py
scan-worker: python worker_runner.py
