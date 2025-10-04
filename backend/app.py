# ---------------------------- app.py ----------------------------
from flask import Flask
from .config import Config
from .extensions import db, migrate, jwt
from .routes import register_routes


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    # Init extensions
    db.init_app(app)
    migrate.init_app(app, db)
    jwt.init_app(app)

    # Register all routes
    register_routes(app)

    # Root check
    @app.route("/")
    def index():
        return {"message": "Restaurant Ordering System API is running"}, 200

    return app


app = create_app()

if __name__ == "__main__":
    app.run(debug=True)
