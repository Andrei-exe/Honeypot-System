# scoring.py - severitatea NU e fixa pe regula; o CALCULAM din ce face botul.
#
# Fiecare actiune valoreaza niste puncte (cat de aproape e de a-ti face rau):
# un scan valoreaza putin, o descarcare de malware valoreaza mult. Punctele unui
# eveniment dau severitatea lui; punctele adunate ale unui atacator dau cat de
# periculos e in ansamblu. E aceeasi idee ca "anomaly scoring" din OWASP CRS:
# aduni puncte si, cand treci un prag, declari gravitatea.
#
# Numerele de mai jos sunt alese de noi (reflecta cat de grav e fiecare pas din
# lantul de atac). Mai tarziu pot fi invatate din date reale, dar ideea ramane:
# severitatea vine din comportament, nu e scrisa de mana pe fiecare regula.

# cate puncte trebuie sa aduni ca sa ajungi la fiecare nivel
SEVERITY_BANDS = [
    (45, "CRITICAL"),
    (25, "HIGH"),
    (10, "MEDIUM"),
    (1, "LOW"),
]


def score_to_severity(score):
    """Puncte -> nivel. 0 puncte = fara amenintare."""
    for threshold, label in SEVERITY_BANDS:
        if score >= threshold:
            return label
    return "NONE"
