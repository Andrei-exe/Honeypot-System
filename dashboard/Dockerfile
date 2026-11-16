# dashboard = pagina web. Cere alertele de la threat-engine (GET /api/alerts), pe portul 8050.
FROM python:3.13-slim

# PYTHONUNBUFFERED=1: print-urile ajung IMEDIAT in `docker logs`.
# PYTHONDONTWRITEBYTECODE=1: fara fisiere .pyc.
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

# Intai doar requirements.txt -> pasul cu pip ramane in cache cat timp nu schimbati bibliotecile.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# User fara drepturi de root. Dashboard-ul nu scrie nimic pe disc -> nu-i trebuie niciun folder de date.
RUN useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin app
USER app

ENV PORT=8050
EXPOSE 8050

# Ca la threat-engine: Python ca PID 1 ignora SIGTERM -> SIGINT (= Ctrl+C) il opreste curat.
STOPSIGNAL SIGINT

CMD ["python", "app.py"]
