"""
ScanNetwork - Network Security Scanner
Flask Web Application Entry Point
"""
from flask import Flask
from flask_cors import CORS
from config import Config
from database import init_db
from scanner.mac_vendor import build_starter_db
import os


def create_app():
    app = Flask(__name__)
    app.secret_key = Config.SECRET_KEY
    CORS(app, resources={r"/api/*": {"origins": "http://127.0.0.1:5000"}})

    # Initialize database
    init_db()

    # Build starter MAC vendor DB if not present
    if not os.path.exists(Config.MAC_VENDOR_DB):
        build_starter_db()

    # Register blueprints
    from routes.api import api
    from routes.ui import ui
    app.register_blueprint(api)
    app.register_blueprint(ui)

    return app


if __name__ == "__main__":
    app = create_app()
    print(f"""
╔══════════════════════════════════════════════╗
║   🛡️  ScanNetwork - Security Scanner         ║
║   Web UI: http://{Config.HOST}:{Config.PORT}          ║
║   Press Ctrl+C to stop                       ║
╚══════════════════════════════════════════════╝
""")
    app.run(
        host=Config.HOST,
        port=Config.PORT,
        debug=Config.DEBUG,
        use_reloader=False,   # disable reloader so background threads survive
    )
