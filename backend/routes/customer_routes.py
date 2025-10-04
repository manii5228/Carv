# routes/customer_routes.py
"""
Customer routes for Carv.

Endpoints:
- POST  /customer/register               -> Register (email/password) (optional if auth handled elsewhere)
- POST  /customer/login                  -> Login (if auth handled elsewhere, keep for dev)
- GET   /customer/restaurants/nearby     -> Nearby restaurants (lat,lng,radius_km)
- GET   /customer/restaurant/<id>/menu   -> Menu items for a restaurant
- POST  /customer/order                  -> Place an order (schedule optional)
- POST  /customer/order/<id>/apply-coupon-> Apply coupon to an order
- POST  /customer/order/<id>/pay         -> Initiate payment (stub - integrate gateway)
- POST  /customer/order/<id>/verify      -> Verify order by otp_code or qr_code_data
- GET   /customer/orders                 -> List customer's orders
- GET   /customer/order/<id>             -> Get order detail
- POST  /customer/order/<id>/cancel      -> Cancel order (if allowed)
- POST  /customer/order/<id>/reorder     -> Reorder a past order
- POST  /customer/favorite/<restaurant>  -> Toggle favorite restaurant
"""

import math
import random
import hashlib
from datetime import datetime, timedelta

from sqlalchemy import func
from functools import wraps
from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import jwt_required, get_jwt_identity, create_access_token, set_access_cookies,unset_jwt_cookies
from backend.extensions import db
from backend.models import (
    User, Restaurant, MenuItem, Order, OrderItem, Payment, Coupon, RewardTransaction,Review
,Cart,CartItem
)

customer_bp = Blueprint("customer", __name__, url_prefix="/customer")

# --------------------- Utilities ---------------------
def haversine_km(lat1, lon1, lat2, lon2):
    R = 6371.0
    phi1 = math.radians(lat1)
    phi2 = math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlambda = math.radians(lon2 - lon1)
    a = math.sin(dphi/2)**2 + math.cos(phi1) * math.cos(phi2) * math.sin(dlambda/2)**2
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1-a))
    return R * c

def now_utc():
    return datetime.utcnow()

def generate_otp():
    return f"{random.randint(100000, 999999):06d}"

def generate_qr_payload(order_id, otp_code, secret_key):
    payload = f"{order_id}-{otp_code}-{secret_key}"
    return hashlib.sha256(payload.encode()).hexdigest()

# OTP expiry in minutes
OTP_TTL_MINUTES = 5


# --------------------- Role Decorator ---------------------
def customer_required(fn):
    """Ensures the user is authenticated AND has role 'customer'."""
    @wraps(fn)
    @jwt_required()
    def wrapper(*args, **kwargs):
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        if not user or user.role != "customer":
            return jsonify({"msg": "customer access required"}), 403
        return fn(*args, **kwargs)
    return wrapper



# --------------------- Auth (dev helpers) ---------------------
@customer_bp.route("/register", methods=["POST"])
def register_customer():
    """
    Simple registration for customers. If your project uses a centralized auth blueprint,
    remove this and rely on auth_routes.
    Body: {name, email, password}
    """
    data = request.get_json() or {}
    email = data.get("email")
    password = data.get("password")
    name = data.get("name", "")

    if not email or not password:
        return jsonify({"msg":"email and password required"}), 400

    if User.query.filter_by(email=email).first():
        return jsonify({"msg":"email already exists"}), 400

    # NOTE: ensure your User model has set_password method or store hash here
    # If using passlib/bcrypt
    try:
        user = User(email=email, name=name, role="customer")
        # If your User model has set_password:
        if hasattr(user, "set_password"):
            user.set_password(password)
        else:
            # fallback (not recommended) - set plain password field 'password_hash' if model supports
            from werkzeug.security import generate_password_hash
            user.password_hash = generate_password_hash(password)
        db.session.add(user)
        db.session.commit()
    except Exception as e:
        current_app.logger.exception("register error")
        return jsonify({"msg":"registration failed"}), 500

    # respond with jwt cookie (optional). For consistency use same auth approach as auth_routes.
    access = create_access_token(identity=user.id)
    resp = jsonify({"msg":"registered", "user_id": user.id})
    set_access_cookies(resp, access)
    return resp, 201

@customer_bp.route("/login", methods=["POST"])
def login_customer():
    """
    Dev login endpoint (if auth handled elsewhere, skip)
    Body: {email, password}
    """
    data = request.get_json() or {}
    email = data.get("email")
    password = data.get("password")
    if not email or not password:
        return jsonify({"msg":"email & password required"}), 400

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({"msg":"invalid credentials"}), 401

    # prefer model method check_password
    if hasattr(user, "check_password"):
        ok = user.check_password(password)
    else:
        from werkzeug.security import check_password_hash
        ok = check_password_hash(getattr(user, "password_hash", ""), password)

    if not ok:
        return jsonify({"msg":"invalid credentials"}), 401

    access = create_access_token(identity=user.id)
    resp = jsonify({"msg":"logged_in", "user_id": user.id})
    set_access_cookies(resp, access)
    return resp

# --------------------- Logout ---------------------
@customer_bp.route("/logout", methods=["POST"])
@customer_required
def customer_logout():
    """
    Logout by clearing JWT cookies.
    """
    resp = jsonify({"msg": "logged out"})
    unset_jwt_cookies(resp)
    return resp, 200
# --------------------- Role Decorator ---------------------
def customer_required(fn):
    """Ensures the user is authenticated AND has role 'customer'."""
    @wraps(fn)
    @jwt_required()
    def wrapper(*args, **kwargs):
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        if not user or user.role != "customer":
            return jsonify({"msg": "customer access required"}), 403
        return fn(*args, **kwargs)
    return wrapper

# --------------------- Profile ---------------------
@customer_bp.route("/profile", methods=["GET"])
@customer_required
def get_profile():
    user_id = get_jwt_identity()
    user = User.query.get_or_404(user_id)
    # include safe profile fields
    return jsonify({
        "id": user.id,
        "name": getattr(user, "name", None),
        "email": getattr(user, "email", None),
        "points": getattr(user, "points", 0)
    })

@customer_bp.route("/profile", methods=["PUT"])
@customer_required
def update_profile():
    user_id = get_jwt_identity()
    user = User.query.get_or_404(user_id)
    data = request.get_json() or {}
    user.name = data.get("name", user.name)
    # optional fields: phone, default_address etc.
    if "phone" in data and hasattr(user, "phone"):
        user.phone = data.get("phone")
    if "default_address" in data and hasattr(user, "default_address"):
        user.default_address = data.get("default_address")
    db.session.commit()
    return jsonify({"msg":"profile updated"})

# --------------------- Restaurant Discovery & Detail ---------------------
@customer_bp.route("/restaurants/nearby", methods=["GET"])
@customer_required
def restaurants_nearby():
    lat = request.args.get("lat", type=float)
    lng = request.args.get("lng", type=float)
    if lat is None or lng is None:
        return jsonify({"msg":"lat and lng required"}), 400
    radius = float(request.args.get("radius_km", current_app.config.get("RADIUS_LIMIT_KM", 7)))

    restaurants = []
    for r in Restaurant.query.filter_by(is_verified=True).all():
        # skip deleted restaurants
        if getattr(r, "is_deleted", False):
            continue
        d = haversine_km(lat, lng, r.latitude, r.longitude)
        if d <= radius:
            restaurants.append({
                "id": r.id,
                "name": r.name,
                "address": r.address,
                "distance_km": round(d, 3),
                "active": getattr(r, "active", True),
                "rating": getattr(r, "rating", None)
            })
    restaurants.sort(key=lambda x: x["distance_km"])
    return jsonify(restaurants)

@customer_bp.route("/restaurant/<int:restaurant_id>", methods=["GET"])
@customer_required
def restaurant_detail(restaurant_id):
    r = Restaurant.query.get_or_404(restaurant_id)
    if getattr(r, "is_deleted", False):
        return jsonify({"msg":"restaurant not available"}), 404
    return jsonify({
        "id": r.id,
        "name": r.name,
        "description": getattr(r, "description", None),
        "address": getattr(r, "address", None),
        "latitude": getattr(r, "latitude", None),
        "longitude": getattr(r, "longitude", None),
        "opening_hours": getattr(r, "opening_hours", None),
        "active": getattr(r, "active", True),
        "rating": getattr(r, "rating", None),
        "gallery": getattr(r, "gallery", [])
    })

@customer_bp.route("/search", methods=["GET"])
@customer_required
def search():
    """
    Query params:
      q (search text), type ('restaurant' or 'menu' or 'all'), limit
    """
    q = request.args.get("q", "").strip()
    search_type = request.args.get("type", "all")
    limit = min(int(request.args.get("limit", 20)), 100)

    if not q:
        return jsonify({"msg":"query required"}), 400

    results = {"restaurants": [], "menu_items": []}

    if search_type in ("restaurant", "all"):
        # simple ILIKE search on restaurant name
        restaurants = Restaurant.query.filter(Restaurant.name.ilike(f"%{q}%")).limit(limit).all()
        for r in restaurants:
            if getattr(r, "is_deleted", False):
                continue
            results["restaurants"].append({"id": r.id, "name": r.name, "address": r.address})

    if search_type in ("menu", "all"):
        menu_items = MenuItem.query.filter(MenuItem.name.ilike(f"%{q}%"), MenuItem.available==True).limit(limit).all()
        for m in menu_items:
            results["menu_items"].append({
                "id": m.id,
                "name": m.name,
                "restaurant_id": m.restaurant_id,
                "price": getattr(m, "price_in_paise", None) / 100.0 if getattr(m, "price_in_paise", None) else getattr(m, "price", None)
            })

    return jsonify(results)
# --------------------- View Menu ---------------------
@customer_bp.route("/restaurant/<int:restaurant_id>/menu", methods=["GET"])
@customer_required
def restaurant_menu(restaurant_id):
    r = Restaurant.query.get_or_404(restaurant_id)
    if getattr(r, "is_deleted", False):
        return jsonify({"msg":"restaurant not available"}), 404
    items = MenuItem.query.filter_by(restaurant_id=r.id, available=True).all()
    out = []
    for it in items:
        price = getattr(it, "price_in_paise", None)
        if price is None:
            price = getattr(it, "price", 0)
            if isinstance(price, float):
                price = int(round(price * 100))
        out.append({
            "id": it.id,
            "name": it.name,
            "description": it.description,
            "price": price / 100.0,
            "price_paise": price
        })
    return jsonify({"restaurant": {"id": r.id, "name": r.name}, "items": out})

# --------------------- Place Order (direct or via cart) ---------------------
@customer_bp.route("/order", methods=["POST"])
@customer_required
def place_order():
    user_id = get_jwt_identity()
    data = request.get_json() or {}

    # If cart_checkout=true, process cart
    cart_checkout = data.get("cart_checkout", False)

    if cart_checkout:
        # Use the checkout_cart logic
        cart = Cart.query.filter_by(user_id=user_id).first()
        if not cart or not cart.items:
            return jsonify({"msg":"cart empty"}), 400

        payment_method = data.get("payment_method", "upi")
        scheduled_time = data.get("scheduled_time")
        restaurant_ids = {ci.menu_item.restaurant_id for ci in cart.items}
        if len(restaurant_ids) != 1:
            return jsonify({"msg":"all items must be from the same restaurant"}), 400
        restaurant_id = restaurant_ids.pop()

        if scheduled_time:
            try:
                scheduled_dt = datetime.fromisoformat(scheduled_time)
            except Exception:
                return jsonify({"msg":"scheduled_time must be ISO format"}), 400
        else:
            scheduled_dt = now_utc()

        total_paise = 0
        order_items_data = []
        for ci in cart.items:
            price_paise = getattr(ci.menu_item, "price_in_paise", 0)
            total_paise += price_paise * ci.quantity
            order_items_data.append((ci.menu_item, ci.quantity, price_paise))

        order = Order(
            user_id=user_id,
            restaurant_id=restaurant_id,
            status="SCHEDULED",
            scheduled_time=scheduled_dt,
            total_amount_paise=total_paise,
            otp_code=generate_otp(),
        )
        secret_key = current_app.config.get("SECRET_KEY","dev-secret")
        db.session.add(order)
        db.session.flush()
        order.qr_code_data = generate_qr_payload(order.id, order.otp_code, secret_key)

        for menu_item, qty, price_paise in order_items_data:
            oi = OrderItem(order_id=order.id, menu_item_id=menu_item.id, quantity=qty, price_in_paise=price_paise)
            db.session.add(oi)

        payment = Payment(order_id=order.id, amount_paise=total_paise, method=payment_method, status="pending")
        db.session.add(payment)

        # Clear cart
        for ci in cart.items:
            db.session.delete(ci)

        db.session.commit()
        return jsonify({
            "msg":"order created from cart",
            "order_id": order.id,
            "total": total_paise / 100.0,
            "otp": order.otp_code,
            "qr_payload": order.qr_code_data,
            "scheduled_time": order.scheduled_time.isoformat()
        }), 201

    else:
        # Direct order without cart
        menu_item_id = data.get("menu_item_id")
        quantity = int(data.get("quantity", 1))
        scheduled_time = data.get("scheduled_time")
        payment_method = data.get("payment_method", "upi")

        if not menu_item_id or quantity <= 0:
            return jsonify({"msg":"menu_item_id and positive quantity required"}), 400

        menu_item = MenuItem.query.get_or_404(menu_item_id)
        if not menu_item.available:
            return jsonify({"msg":"menu item not available"}), 400

        restaurant_id = menu_item.restaurant_id

        if scheduled_time:
            try:
                scheduled_dt = datetime.fromisoformat(scheduled_time)
            except Exception:
                return jsonify({"msg":"scheduled_time must be ISO format"}), 400
        else:
            scheduled_dt = now_utc()

        total_paise = menu_item.price_in_paise * quantity

        order = Order(
            user_id=user_id,
            restaurant_id=restaurant_id,
            status="SCHEDULED",
            scheduled_time=scheduled_dt,
            total_amount_paise=total_paise,
            otp_code=generate_otp(),
        )
        secret_key = current_app.config.get("SECRET_KEY","dev-secret")
        db.session.add(order)
        db.session.flush()
        order.qr_code_data = generate_qr_payload(order.id, order.otp_code, secret_key)

        order_item = OrderItem(order_id=order.id, menu_item_id=menu_item.id, quantity=quantity, price_in_paise=menu_item.price_in_paise)
        db.session.add(order_item)

        payment = Payment(order_id=order.id, amount_paise=total_paise, method=payment_method, status="pending")
        db.session.add(payment)

        db.session.commit()
        return jsonify({
            "msg":"direct order created",
            "order_id": order.id,
            "total": total_paise / 100.0,
            "otp": order.otp_code,
            "qr_payload": order.qr_code_data,
            "scheduled_time": order.scheduled_time.isoformat()
        }), 201

# ---------------- Get Order Details ----------------
@customer_bp.route("/order/<int:order_id>", methods=["GET"])
@jwt_required()
def get_order_details(order_id):
    user_id = get_jwt_identity()
    order = Order.query.filter_by(id=order_id, customer_id=user_id).first()
    if not order:
        return jsonify({"error": "Order not found"}), 404

    items = [
        {
            "menu_item": MenuItem.query.get(oi.menu_item_id).name,
            "quantity": oi.quantity,
            "price": oi.price,
            "subtotal": oi.price * oi.quantity
        }
        for oi in order.items
    ]

    return jsonify({
        "order_id": order.id,
        "status": order.status,
        "created_at": order.created_at,
        "items": items,
        "total_amount": sum(i["subtotal"] for i in items)
    })

# --------------------- Apply Coupon ---------------------
@customer_bp.route("/order/<int:order_id>/apply-coupon", methods=["POST"])
@customer_required
def apply_coupon(order_id):
    user_id = get_jwt_identity()
    data = request.get_json() or {}
    code = data.get("code")
    if not code:
        return jsonify({"msg":"coupon code required"}), 400

    order = Order.query.get_or_404(order_id)
    if order.user_id != user_id:
        return jsonify({"msg":"forbidden"}), 403
    if order.status != "SCHEDULED":
        return jsonify({"msg":"cannot apply coupon at this stage"}), 400

    coupon = Coupon.query.filter_by(code=code.upper(), is_active=True).first()
    if not coupon:
        return jsonify({"msg":"invalid coupon"}), 404

    now = now_utc()
    if coupon.valid_from and now < coupon.valid_from:
        return jsonify({"msg":"coupon not active yet"}), 400
    if coupon.valid_to and now > coupon.valid_to:
        return jsonify({"msg":"coupon expired"}), 400
    if getattr(coupon, "usage_limit", None) and coupon.usage_count >= coupon.usage_limit:
        return jsonify({"msg":"coupon usage limit reached"}), 400
    if getattr(coupon, "min_order_amount_paise", 0) and order.total_amount_paise < coupon.min_order_amount_paise:
        return jsonify({"msg":"order does not meet minimum amount for coupon"}), 400

    discount_paise = 0
    if getattr(coupon, "discount_percent", None):
        discount_paise = (order.total_amount_paise * coupon.discount_percent) // 100
    elif getattr(coupon, "discount_paise", None):
        discount_paise = coupon.discount_paise

    order.total_amount_paise = max(0, order.total_amount_paise - discount_paise)
    coupon.usage_count = (coupon.usage_count or 0) + 1
    db.session.commit()
    return jsonify({"msg":"coupon_applied", "new_total": order.total_amount_paise / 100.0, "discount": discount_paise / 100.0})

# --------------------- Initiate Payment (stub) ---------------------
@customer_bp.route("/order/<int:order_id>/pay", methods=["POST"])
@customer_required
def pay_order(order_id):
    user_id = get_jwt_identity()
    order = Order.query.get_or_404(order_id)
    if order.user_id != user_id:
        return jsonify({"msg":"forbidden"}), 403
    if order.status != "SCHEDULED":
        return jsonify({"msg":"cannot pay at this stage"}), 400

    if hasattr(order, "payment") and order.payment:
        payment = order.payment
        payment.status = "success"
        payment.transaction_id = f"dev-{order.id}-{int(datetime.utcnow().timestamp())}"
    else:
        payment = Payment(order_id=order.id, amount_paise=order.total_amount_paise, method=request.json.get("method","upi"), status="success", transaction_id=f"dev-{order.id}")
        db.session.add(payment)

    order.status = "PREPARING"
    db.session.commit()
    return jsonify({"msg":"payment_success", "order_id": order.id, "status": order.status})

# --------------------- Verify Order (OTP / QR) ---------------------
# NOTE: verification may be done by restaurant terminal so this can be public (no customer_required)
@customer_bp.route("/order/<int:order_id>/verify", methods=["POST"])
def verify_order(order_id):
    data = request.get_json() or {}
    otp = data.get("otp")
    qr = data.get("qr_payload")

    order = Order.query.get_or_404(order_id)
    if order.status not in ("SCHEDULED", "PREPARING"):
        return jsonify({"msg":"order not in verifiable state"}), 400

    if otp:
        if not order.otp_code:
            return jsonify({"msg":"no otp available for this order"}), 400
        expiry = order.created_at + timedelta(minutes=OTP_TTL_MINUTES)
        if now_utc() > expiry:
            return jsonify({"msg":"otp expired"}), 400
        if otp == order.otp_code:
            order.verified_at = now_utc()
            order.status = "READY"
            db.session.commit()
            return jsonify({"msg":"verified", "status": order.status}), 200
        else:
            return jsonify({"msg":"invalid otp"}), 400

    if qr:
        if not order.qr_code_data:
            return jsonify({"msg":"no qr set for this order"}), 400
        if qr == order.qr_code_data:
            order.verified_at = now_utc()
            order.status = "READY"
            db.session.commit()
            return jsonify({"msg":"verified", "status": order.status}), 200
        else:
            return jsonify({"msg":"invalid qr payload"}), 400

    return jsonify({"msg":"otp or qr_payload required"}), 400

# --------------------- Orders (list/get) ---------------------
@customer_bp.route("/orders", methods=["GET"])
@customer_required
def list_orders():
    user_id = get_jwt_identity()
    rows = Order.query.filter_by(user_id=user_id).order_by(Order.created_at.desc()).all()
    def serialize(o):
        return {
            "id": o.id,
            "restaurant_id": o.restaurant_id,
            "status": getattr(o, "status", None),
            "total": getattr(o, "total_amount_paise", 0) / 100.0,
            "scheduled_time": o.scheduled_time.isoformat() if getattr(o, "scheduled_time", None) else None,
            "otp": o.otp_code if current_app.config.get("ENV","dev") == "dev" else None,
            "created_at": o.created_at.isoformat()
        }
    return jsonify([serialize(r) for r in rows])

@customer_bp.route("/order/<int:order_id>", methods=["GET"])
@customer_required
def get_order(order_id):
    user_id = get_jwt_identity()
    o = Order.query.get_or_404(order_id)
    if o.user_id != user_id:
        return jsonify({"msg":"forbidden"}), 403
    return jsonify({
        "id": o.id,
        "restaurant_id": o.restaurant_id,
        "status": getattr(o, "status", None),
        "items": [
            {
                "menu_item_id": it.menu_item_id,
                "quantity": it.quantity,
                "price": (getattr(it, "price_in_paise", None) / 100.0) if getattr(it, "price_in_paise", None) else None
            } for it in o.items
        ],
        "total": o.total_amount_paise / 100.0,
        "scheduled_time": o.scheduled_time.isoformat(),
        "otp": o.otp_code if current_app.config.get("ENV","dev") == "dev" else None
    })

# --------------------- Cancel / Refund ---------------------
@customer_bp.route("/order/<int:order_id>/cancel", methods=["PUT"])
@jwt_required()
def cancel_order(order_id):
    user_id = get_jwt_identity()
    order = Order.query.filter_by(id=order_id, customer_id=user_id).first()
    if not order:
        return jsonify({"error": "Order not found"}), 404

    if order.status in ["Completed", "Cancelled"]:
        return jsonify({"error": "Order cannot be cancelled"}), 400

    order.status = "Cancelled"
    db.session.commit()
    return jsonify({"message": "Order cancelled"}), 200


@customer_bp.route("/order/<int:order_id>/refund", methods=["POST"])
@customer_required
def request_refund(order_id):
    """
    Customer can request refund — this endpoint marks payment as refund_requested.
    Real refund processing should be handled asynchronously by admin/payment provider.
    """
    user_id = get_jwt_identity()
    order = Order.query.get_or_404(order_id)
    if order.user_id != user_id:
        return jsonify({"msg":"forbidden"}), 403
    if not hasattr(order, "payment") or not order.payment:
        return jsonify({"msg":"no payment found for this order"}), 400
    payment = order.payment
    # set a status to indicate refund request - adjust to your Payment model
    payment.status = getattr(payment, "status", "refund_requested")
    db.session.commit()
    return jsonify({"msg":"refund_requested"}), 200

# --------------------- Reorder ---------------------
@customer_bp.route("/order/<int:order_id>/reorder", methods=["POST"])
@customer_required
def reorder(order_id):
    user_id = get_jwt_identity()
    previous = Order.query.get_or_404(order_id)
    if previous.user_id != user_id:
        return jsonify({"msg":"forbidden"}), 403

    new_order = Order(
        user_id=user_id,
        restaurant_id=previous.restaurant_id,
        status="SCHEDULED",
        scheduled_time=now_utc(),
        total_amount_paise=previous.total_amount_paise
    )
    new_order.otp_code = generate_otp()
    secret_key = current_app.config.get("SECRET_KEY","dev-secret")
    db.session.add(new_order)
    db.session.flush()
    new_order.qr_code_data = generate_qr_payload(new_order.id, new_order.otp_code, secret_key)

    for it in previous.items:
        oi = OrderItem(order_id=new_order.id, menu_item_id=it.menu_item_id, quantity=it.quantity)
        if hasattr(oi, "price_in_paise"):
            oi.price_in_paise = getattr(it, "price_in_paise", None) or 0
        db.session.add(oi)

    if hasattr(Payment, "__table__"):
        payment = Payment(order_id=new_order.id, amount_paise=new_order.total_amount_paise, method="upi", status="pending")
        db.session.add(payment)

    db.session.commit()
    return jsonify({"msg":"reorder_created", "order_id": new_order.id, "otp": new_order.otp_code}), 201

# --------------------- Favorites ---------------------
@customer_bp.route("/favorite/<int:restaurant_id>", methods=["POST"])
@customer_required
def toggle_favorite(restaurant_id):
    user_id = get_jwt_identity()
    user = User.query.get_or_404(user_id)
    restaurant = Restaurant.query.get_or_404(restaurant_id)

    if hasattr(user, "favorites"):
        if restaurant in user.favorites:
            user.favorites.remove(restaurant)
            db.session.commit()
            return jsonify({"msg": "removed from favorites"})
        else:
            user.favorites.append(restaurant)
            db.session.commit()
            return jsonify({"msg": "added to favorites"})
    else:
        return jsonify({"msg": "favorites not supported on User model"}), 400

@customer_bp.route("/favorites", methods=["GET"])
@customer_required
def list_favorites():
    user_id = get_jwt_identity()
    user = User.query.get_or_404(user_id)
    if not hasattr(user, "favorites"):
        return jsonify({"msg": "favorites not supported on User model"}), 400
    favs = []
    for r in user.favorites:
        favs.append({"id": r.id, "name": r.name, "address": r.address})
    return jsonify({"favorites": favs})

# --------------------- Reviews ---------------------
@customer_bp.route("/order/<int:order_id>/review", methods=["POST"])
@customer_required
def create_review(order_id):
    user_id = get_jwt_identity()
    data = request.get_json() or {}
    rating = data.get("rating")
    comment = data.get("comment", "")

    if rating is None:
        return jsonify({"msg":"rating required"}), 400
    if not (1 <= int(rating) <= 5):
        return jsonify({"msg":"rating must be 1-5"}), 400

    order = Order.query.get_or_404(order_id)
    if order.user_id != user_id:
        return jsonify({"msg":"forbidden"}), 403
    # only allow review after completion
    if getattr(order, "status", None) != "COMPLETED" and getattr(order, "status", None) != "COMPLETED".lower():
        # allow posting reviews for completed orders only
        return jsonify({"msg":"can only review completed orders"}), 400

    review = Review(
        user_id=user_id,
        restaurant_id=order.restaurant_id,
        rating=int(rating),
        comment=comment
    )
    db.session.add(review)
    db.session.commit()
    return jsonify({"msg":"review created", "review_id": review.id}), 201

@customer_bp.route("/reviews", methods=["GET"])
@customer_required
def my_reviews():
    user_id = get_jwt_identity()
    rows = Review.query.filter_by(user_id=user_id).order_by(Review.created_at.desc()).all()
    out = [{"id": r.id, "restaurant_id": r.restaurant_id, "rating": r.rating, "comment": r.comment} for r in rows]
    return jsonify({"reviews": out})

@customer_bp.route("/review/<int:order_id>", methods=["POST"])
@jwt_required()
def leave_review(order_id):
    """
    Leave review for a completed order.
    JSON: { "menu_item_id": 1, "rating": 5, "comment": "Great taste!" }
    """
    user_id = get_jwt_identity()
    data = request.get_json()
    order = Order.query.filter_by(id=order_id, customer_id=user_id).first()

    if not order:
        return jsonify({"error": "Order not found"}), 404
    if order.status != "Completed":
        return jsonify({"error": "Review can only be added for completed orders"}), 400

    review = Review(
        user_id=user_id,
        order_id=order.id,
        menu_item_id=data.get("menu_item_id"),
        rating=data.get("rating"),
        comment=data.get("comment"),
        created_at=datetime.utcnow()
    )
    db.session.add(review)
    db.session.commit()
    return jsonify({"message": "Review added"}), 201

# --------------------- Rewards ---------------------
@customer_bp.route("/rewards", methods=["GET"])
@customer_required
def get_rewards():
    user_id = get_jwt_identity()
    # compute balance: sum earns - sum redeems
    earns = db.session.query(func.coalesce(func.sum(RewardTransaction.points), 0)).filter_by(user_id=user_id, type="earn").scalar() or 0
    redeems = db.session.query(func.coalesce(func.sum(RewardTransaction.points), 0)).filter_by(user_id=user_id, type="redeem").scalar() or 0
    balance = earns - redeems
    transactions = RewardTransaction.query.filter_by(user_id=user_id).order_by(RewardTransaction.created_at.desc()).limit(50).all()
    tx = [{"id": t.id, "points": t.points, "type": t.type, "order_id": getattr(t, "order_id", None), "created_at": t.created_at.isoformat()} for t in transactions]
    return jsonify({"balance": balance, "transactions": tx})

@customer_bp.route("/rewards/redeem", methods=["POST"])
@customer_required
def redeem_rewards():
    user_id = get_jwt_identity()
    data = request.get_json() or {}
    points = int(data.get("points", 0))
    if points <= 0:
        return jsonify({"msg":"invalid points"}), 400

    # compute balance
    earns = db.session.query(func.coalesce(func.sum(RewardTransaction.points), 0)).filter_by(user_id=user_id, type="earn").scalar() or 0
    redeems = db.session.query(func.coalesce(func.sum(RewardTransaction.points), 0)).filter_by(user_id=user_id, type="redeem").scalar() or 0
    balance = earns - redeems
    if points > balance:
        return jsonify({"msg":"not enough points"}), 400

    rt = RewardTransaction(user_id=user_id, points=points, type="redeem", order_id=None)
    db.session.add(rt)
    db.session.commit()
    return jsonify({"msg":"redeemed", "balance": balance - points})

# --------------------- Notifications placeholder ---------------------
@customer_bp.route("/notifications", methods=["GET"])
@customer_required
def get_notifications():
    # placeholder: implement notification model / queue
    return jsonify({"notifications": []})

# --------------------- Misc helpers / health ---------------------
@customer_bp.route("/ping", methods=["GET"])
def ping():
    return jsonify({"msg":"pong"})

# --------------------- Customer Cart Routes ---------------------

@customer_bp.route("/cart/add", methods=["POST"])
@customer_required
def add_to_cart():
    user_id = get_jwt_identity()
    data = request.get_json() or {}
    menu_item_id = data.get("menu_item_id")
    quantity = int(data.get("quantity", 1))

    if not menu_item_id or quantity <= 0:
        return jsonify({"msg":"menu_item_id and positive quantity required"}), 400

    menu_item = MenuItem.query.get_or_404(menu_item_id)
    if not menu_item.available:
        return jsonify({"msg":"menu item not available"}), 400

    # get or create cart
    cart = Cart.query.filter_by(user_id=user_id).first()
    if not cart:
        cart = Cart(user_id=user_id)
        db.session.add(cart)
        db.session.flush()

    # check if item exists in cart
    cart_item = CartItem.query.filter_by(cart_id=cart.id, menu_item_id=menu_item_id).first()
    if cart_item:
        cart_item.quantity += quantity
    else:
        cart_item = CartItem(cart_id=cart.id, menu_item_id=menu_item_id, quantity=quantity)
        db.session.add(cart_item)

    db.session.commit()
    return jsonify({"msg":"added to cart", "cart_id": cart.id}), 201

# View cart
@customer_bp.route("/cart", methods=["GET"])
@customer_required
def view_cart():
    user_id = get_jwt_identity()
    cart = Cart.query.filter_by(user_id=user_id).first()
    if not cart or not cart.items:
        return jsonify({"msg":"cart empty", "items": []})

    items = []
    total_paise = 0
    for ci in cart.items:
        price = getattr(ci.menu_item, "price_in_paise", 0)
        total_paise += price * ci.quantity
        items.append({
            "cart_item_id": ci.id,
            "menu_item_id": ci.menu_item_id,
            "name": ci.menu_item.name,
            "quantity": ci.quantity,
            "price": price / 100.0,
            "total": (price * ci.quantity) / 100.0
        })

    return jsonify({"items": items, "total": total_paise / 100.0})

# Update cart item quantity
@customer_bp.route("/cart/update/<int:cart_item_id>", methods=["PUT"])
@customer_required
def update_cart_item(cart_item_id):
    user_id = get_jwt_identity()
    cart_item = CartItem.query.get_or_404(cart_item_id)
    cart = Cart.query.get(cart_item.cart_id)
    if cart.user_id != user_id:
        return jsonify({"msg":"forbidden"}), 403

    data = request.get_json() or {}
    quantity = int(data.get("quantity", 0))
    if quantity <= 0:
        db.session.delete(cart_item)
        db.session.commit()
        return jsonify({"msg":"item removed from cart"})

    cart_item.quantity = quantity
    db.session.commit()
    return jsonify({"msg":"cart item updated", "cart_item_id": cart_item.id, "quantity": cart_item.quantity})

# Remove item from cart
@customer_bp.route("/cart/remove/<int:cart_item_id>", methods=["DELETE"])
@customer_required
def remove_cart_item(cart_item_id):
    user_id = get_jwt_identity()
    cart_item = CartItem.query.get_or_404(cart_item_id)
    cart = Cart.query.get(cart_item.cart_id)
    if cart.user_id != user_id:
        return jsonify({"msg":"forbidden"}), 403

    db.session.delete(cart_item)
    db.session.commit()
    return jsonify({"msg":"item removed from cart"})

# Checkout cart → create order
@customer_bp.route("/cart/checkout", methods=["POST"])
@customer_required
def checkout_cart():
    user_id = get_jwt_identity()
    cart = Cart.query.filter_by(user_id=user_id).first()
    if not cart or not cart.items:
        return jsonify({"msg":"cart empty"}), 400

    data = request.get_json() or {}
    scheduled_time = data.get("scheduled_time")
    payment_method = data.get("payment_method", "upi")

    # all items must belong to the same restaurant
    restaurant_ids = {ci.menu_item.restaurant_id for ci in cart.items}
    if len(restaurant_ids) != 1:
        return jsonify({"msg":"all items must be from the same restaurant"}), 400
    restaurant_id = restaurant_ids.pop()

    if scheduled_time:
        try:
            scheduled_dt = datetime.fromisoformat(scheduled_time)
        except Exception:
            return jsonify({"msg":"scheduled_time must be ISO format"}), 400
    else:
        scheduled_dt = now_utc()

    total_paise = 0
    order_items_data = []
    for ci in cart.items:
        price_paise = getattr(ci.menu_item, "price_in_paise", 0)
        total_paise += price_paise * ci.quantity
        order_items_data.append((ci.menu_item, ci.quantity, price_paise))

    # create order
    order = Order(
        user_id=user_id,
        restaurant_id=restaurant_id,
        status="SCHEDULED",
        scheduled_time=scheduled_dt,
        total_amount_paise=total_paise,
        otp_code=generate_otp(),
    )
    secret_key = current_app.config.get("SECRET_KEY","dev-secret")
    db.session.add(order)
    db.session.flush()
    order.qr_code_data = generate_qr_payload(order.id, order.otp_code, secret_key)

    for menu_item, qty, price_paise in order_items_data:
        oi = OrderItem(order_id=order.id, menu_item_id=menu_item.id, quantity=qty, price_in_paise=price_paise)
        db.session.add(oi)

    payment = Payment(order_id=order.id, amount_paise=total_paise, method=payment_method, status="pending")
    db.session.add(payment)

    # clear cart
    for ci in cart.items:
        db.session.delete(ci)

    db.session.commit()
    return jsonify({
        "msg":"order created from cart",
        "order_id": order.id,
        "total": total_paise / 100.0,
        "otp": order.otp_code,
        "qr_payload": order.qr_code_data,
        "scheduled_time": order.scheduled_time.isoformat()
    }), 201
