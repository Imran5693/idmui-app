from flask import Blueprint
from datetime import datetime

bp = Blueprint('keystone', __name__)

from keystone import routes  # Import routes to attach to blueprint

@bp.app_template_filter('format_datetime')
def format_datetime(value):
    if not value:
        return '-'
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").strftime('%Y-%m-%d %H:%M')
    except:
        return value

@bp.app_template_filter('is_expired')
def is_expired(value):
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ") < datetime.utcnow()
    except:
        return False

# Make this available to app.py
def format_bytes(value):
    try:
        value = float(value)
        if value < 1024:
            return f"{value:.2f} KB"
        elif value < 1024 ** 2:
            return f"{value / 1024:.2f} MB"
        elif value < 1024 ** 3:
            return f"{value / (1024 ** 2):.2f} GB"
        else:
            return f"{value / (1024 ** 3):.2f} TB"
    except (TypeError, ValueError):
        return "N/A"

def format_number(value):
    try:
        return f"{int(value):,}"
    except (ValueError, TypeError):
        return value
