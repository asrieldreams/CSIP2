from flask import Flask
from flask_cors import CORS
from config import Config
from extensions import db
from routes.auth    import auth_bp
from routes.scams   import scams_bp
from routes.admin   import admin_bp
from routes.scanner import scanner_bp


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    # Allow all origins for /api/* so your HTML pages can call the backend.
    # In production, replace "*" with your actual domain.
    CORS(app, resources={r"/api/*": {
    "origins": "*",
    "methods": ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    "allow_headers": ["Content-Type", "Authorization"]
}})

    db.init_app(app)

    # Register blueprints
    app.register_blueprint(auth_bp,    url_prefix='/api/auth')
    app.register_blueprint(scams_bp,   url_prefix='/api')
    app.register_blueprint(admin_bp,   url_prefix='/api/admin')
    app.register_blueprint(scanner_bp, url_prefix='/api/scanner')

    return app


if __name__ == '__main__':
    app = create_app()
    app.run(debug=True, port=5000)
