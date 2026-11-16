# threat-engine = receiver.py: primeste evenimentele de la agent (POST /api/events),
# face alertele in timp real si le da dashboard-ului (GET /api/alerts), pe portul 8000.
FROM python:3.13-slim

# PYTHONUNBUFFERED=1: print-urile ajung IMEDIAT in `docker logs`
# (altfel Python le tine intr-un buffer si apar cu intarziere sau deloc).
# PYTHONDONTWRITEBYTECODE=1: fara fisiere .pyc (oricum nu poate scrie in /app, vezi mai jos).
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

# Intai doar requirements.txt: Docker tine minte (cache) pasul cu pip
# si nu reinstaleaza Flask la fiecare build, cat timp nu schimbati bibliotecile.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# User fara drepturi de root + folderul pentru date. Codul din /app ramane al lui root
# (aplicatia nu-si poate modifica propriul cod), iar /data e singurul loc unde scrie.
RUN useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin app \
    && mkdir /data && chown app:app /data
USER app

# Unde scrie receiver.py (le citeste din variabile de mediu) -> pe volum, ca sa nu se piarda.
# SESSIONS_FILE e pentru main.py (vezi chichite: trebuie o linie schimbata in main.py ca s-o citeasca).
ENV EVENTS_FILE=/data/received_events.jsonl \
    ALERTS_FILE=/data/alerts.jsonl \
    SESSIONS_FILE=/data/sessions.json \
    PORT=8000

EXPOSE 8000

# `docker stop` trimite implicit SIGTERM. Python, ca proces principal in container (PID 1),
# il ignora -> Docker astepta 10s si apoi il omora fortat (testat: 10,2s, cod 137).
# SIGINT = ca un Ctrl+C -> Flask se opreste curat, imediat.
STOPSIGNAL SIGINT

CMD ["python", "receiver.py"]
