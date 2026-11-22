"""HTML rendering routes for the web interface."""

from flask import Blueprint, render_template

views_bp = Blueprint("views_bp", __name__)


@views_bp.get("/")
def index():
    return render_template("index.html")
