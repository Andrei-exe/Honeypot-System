# threat-engine = receiver.py on port 8000: receives the agent's events (POST /api/events),
# raises real-time alerts and serves them to the dashboard (GET /api/alerts).
FROM python:3.13-slim

# PYTHONUNBUFFERED=1: prints show up in `docker logs` RIGHT AWAY (not late or never, from a buffer).
# PYTHONDONTWRITEBYTECODE=1: no .pyc files (it can't write to /app anyway, see below).
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

# requirements.txt first: Docker caches the pip step and doesn't reinstall Flask on every build,
# as long as the libraries don't change.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Non-root user + data folder. The code in /app stays owned by root (the app can't modify
# its own code); /data is the only place it writes to.
RUN useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin app \
    && mkdir /data && chown app:app /data
USER app

# Where receiver.py writes (read from env vars) -> on the volume, so nothing is lost.
# DB_FILE = the SQLite database (events + alerts; SQLite adds -wal / -shm files next to it, also in /data).
# EVENTS_FILE = the journal: every event exactly as received, the database can be rebuilt from it.
# REJECTED_FILE = events that failed validation (kept with the reason, not dropped).
# SESSIONS_FILE is used by main.py (offline analysis).
ENV DB_FILE=/data/honeypot.db \
    EVENTS_FILE=/data/received_events.jsonl \
    REJECTED_FILE=/data/rejected_events.jsonl \
    SESSIONS_FILE=/data/sessions.json \
    PORT=8000

EXPOSE 8000

# `docker stop` sends SIGTERM, which Python as PID 1 ignores -> Docker kills it after 10s (exit 137).
# SIGINT = Ctrl+C -> Flask stops cleanly, right away.
STOPSIGNAL SIGINT

CMD ["python", "receiver.py"]
