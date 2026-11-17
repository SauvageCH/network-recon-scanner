"""Flask application factory."""
from flask import Flask

from app import storage


def create_app() -> Flask:
    app = Flask(__name__)
    storage.init_db()
    from app.routes import bp
    app.register_blueprint(bp)
    return app
