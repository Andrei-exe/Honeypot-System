"""HTML rendering routes for the web interface."""

from flask import Blueprint, render_template

from services.engine_client import EngineError, engine_client

views_bp = Blueprint("views_bp", __name__)


@views_bp.get("/")
def index():
    initial_alerts = []
    try:
        data = engine_client.get_alerts()
        initial_alerts = data.get("alerts") or []
    except EngineError:
        initial_alerts = []
    return render_template("index.html", initial_alerts=initial_alerts)
