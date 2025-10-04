from .customer_routes import customer_bp
from .restaurant_routes import restaurant_bp
from .admin_routes import admin_bp

def register_routes(app):
    app.register_blueprint(customer_bp, url_prefix="/customer")
    app.register_blueprint(restaurant_bp, url_prefix="/restaurants")
    app.register_blueprint(admin_bp, url_prefix="/admin")