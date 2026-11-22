"""Flask entrypoint for the Honeypot SOC Dashboard console."""

from flask import Flask

from config import PORT, THREAT_ENGINE_URL
from routes.api import api_bp
from routes.exports import exports_bp
from routes.views import views_bp


def create_app():
    app = Flask(__name__)
    app.config["JSON_SORT_KEYS"] = False

    app.register_blueprint(views_bp)
    app.register_blueprint(api_bp)
    app.register_blueprint(exports_bp)

    @app.after_request
    def apply_security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "connect-src 'self'; "
            "font-src 'self'; "
            "frame-ancestors 'none'; "
            "base-uri 'self'"
        )
        return response

    return app


app = create_app()


if __name__ == "__main__":
    print(f"SOC dashboard running on http://0.0.0.0:{PORT} | upstream: {THREAT_ENGINE_URL}")
    app.run(host="0.0.0.0", port=PORT, threaded=True)
