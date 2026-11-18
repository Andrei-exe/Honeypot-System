import os

try:
    import geoip2.database
    import geoip2.errors
    GEOIP_INSTALLED = True
except ImportError:
    GEOIP_INSTALLED = False

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
GEOIP_DB = os.environ.get("GEOIP_DB", os.path.join(BASE_DIR, "GeoLite2-City.mmdb"))

reader = None
cache = {}


def geo_available():
    """True daca avem si biblioteca geoip2, si fisierul cu baza de date."""
    return GEOIP_INSTALLED and os.path.exists(GEOIP_DB)


def open_reader():
    global reader
    if reader is None and geo_available():
        reader = geoip2.database.Reader(GEOIP_DB)
    return reader


def geo_lookup(ip):
    """Tara, orasul si coordonatele unui IP. None daca nu stim (IP privat, lipsa bazei)."""
    if ip in cache:
        return cache[ip]

    result = None
    db = open_reader()
    if db is not None and ip:
        try:
            answer = db.city(ip)
            result = {
                "country_code": answer.country.iso_code,
                "country": answer.country.name,
                "city": answer.city.name,
                "lat": answer.location.latitude,
                "lon": answer.location.longitude,
            }
        except (geoip2.errors.AddressNotFoundError, ValueError):
            result = None

    cache[ip] = result
    return result
