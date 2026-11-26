# storage.py - unde se salveaza evenimentele, alertele si evenimentele respinse.
#
# Acum: fisiere JSONL (JsonlStorage). Baza de date va fi o clasa noua cu ACELEASI metode:
#   save(events, alerts, rejected)  un lot intreg, totul sau nimic (in DB: o singura tranzactie)
#   iter_events() / iter_alerts()   la pornire, ce e deja salvat (in DB: SELECT ... ORDER BY)
# Restul codului (engine.py) nu stie daca sub el e un fisier sau o baza de date.
#
# Ce se salveaza:
#   evenimentul = exact ce a trimis agentul + event_id (vezi events.py)
#   alerta      = alert_id, event_id, codul regulii, scorul... FARA copia evenimentului (filters.build_alert)
#   respinsul   = {received_at, reason, item}: ce n-a trecut de validare, ca sa nu se piarda nimic

import json
import os


def iter_jsonl(path):
    """Citeste un fisier JSONL LINIE CU LINIE (generator): memoria ramane marginita,
    oricat de mare ar fi fisierul. Liniile stricate sunt sarite."""
    if not os.path.exists(path):
        return
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line == "":
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue


def append_lines(path, items, ascii_only=False):
    """Adauga fiecare element ca o linie JSON la finalul fisierului, dintr-o singura scriere."""
    text = "".join(json.dumps(item, ensure_ascii=ascii_only) + "\n" for item in items)
    with open(path, "a", encoding="utf-8") as f:
        f.write(text)


class JsonlStorage:
    def __init__(self, events_file, alerts_file, rejected_file):
        self.events_file = events_file
        self.alerts_file = alerts_file
        self.rejected_file = rejected_file

    def save(self, events, alerts, rejected=()):
        """Salveaza un lot: totul sau nimic. Daca o scriere pica (disc plin), taiem fisierele
        inapoi la marimea de dinainte, ca un lot retrimis sa nu apara de doua ori."""
        # respinsele cu ascii_only: pot avea text care nu se poate scrie altfel (ex. "\ud800")
        parts = [(self.events_file, events, False), (self.alerts_file, alerts, False),
                 (self.rejected_file, rejected, True)]
        sizes = {}
        try:
            for path, items, ascii_only in parts:
                if not items:
                    continue
                sizes[path] = os.path.getsize(path) if os.path.exists(path) else 0
                append_lines(path, items, ascii_only)
        except BaseException:
            for path, size in sizes.items():
                try:
                    os.truncate(path, size)
                except OSError:
                    pass
            raise

    def iter_events(self):
        return iter_jsonl(self.events_file)

    def iter_alerts(self):
        return iter_jsonl(self.alerts_file)


class MemoryStorage:
    """Tine totul in liste, in RAM. Pentru main.py (analiza unui fisier) si pentru teste."""

    def __init__(self):
        self.events = []
        self.alerts = []
        self.rejected = []

    def save(self, events, alerts, rejected=()):
        self.events.extend(events)
        self.alerts.extend(alerts)
        self.rejected.extend(rejected)

    def iter_events(self):
        return iter(list(self.events))

    def iter_alerts(self):
        return iter(list(self.alerts))
