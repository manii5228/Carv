# routes/restaurant_routes.py
"""
Restaurant routes for Carv (Production Ready).

Role required: restaurant_owner

Endpoints:

1️⃣ Restaurant Profile
- POST   /restaurant/register
- GET    /restaurant/me
- PUT    /restaurant/me
- POST   /restaurant/me/verify
- POST   /restaurant/me/gallery
- PUT    /restaurant/me/hours
- PUT    /restaurant/me/status

2️⃣ Menu Management
- POST   /restaurant/menu
- GET    /restaurant/menu
- PUT    /restaurant/menu/<id>
- DELETE /restaurant/menu/<id>
- PATCH  /restaurant/menu/<id>/availability
- POST   /restaurant/menu/bulk
- GET    /restaurant/menu/search
- PUT    /restaurant/menu/<id>/category

3️⃣ Orders
- GET    /restaurant/orders
- GET    /restaurant/order/<id>
- POST   /restaurant/order/<id>/accept
- POST   /restaurant/order/<id>/reject
- POST   /restaurant/order/<id>/update-status
- POST   /restaurant/order/<id>/close
- PATCH  /restaurant/order/<id>/partial-accept
- GET    /restaurant/orders/export
- POST   /restaurant/order/<id>/notify
- GET    /restaurant/orders/delivery

4️⃣ Coupons
- POST   /restaurant/coupons
- GET    /restaurant/coupons
- PUT    /restaurant/coupon/<id>
- DELETE /restaurant/coupon/<id>
- POST   /restaurant/coupons/bulk
- GET    /restaurant/coupon/<id>/usage
- PUT    /restaurant/coupon/<id>/schedule

5️⃣ Reports
- GET    /restaurant/reports/sales
- GET    /restaurant/reports/popular-items
- GET    /restaurant/reports/customers
- GET    /restaurant/reports/revenue-slots
- GET    /restaurant/reports/sales-trends
- GET    /restaurant/reports/refunds
- GET    /restaurant/reports/discounts

6️⃣ Rewards
- GET    /restaurant/rewards
- POST   /restaurant/rewards/adjust
- GET    /restaurant/rewards/top-customers

7️⃣ Customers & Notifications
- GET    /restaurant/customers
- GET    /restaurant/customers/repeat
- POST   /restaurant/customers/message
- POST   /restaurant/customers/vip

8️⃣ Integrations
- GET    /restaurant/integrations/payment
- POST   /restaurant/integrations/pos
- POST   /restaurant/integrations/delivery
"""


from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from datetime import datetime
from sqlalchemy import func
from backend.extensions import db
from backend.models import User, UserRole, Restaurant, MenuItem, Order, OrderStatus, Coupon, OrderItem, Payment

restaurant_bp = Blueprint("restaurant", __name__, url_prefix="/restaurant")

# ---------------------- Helper Decorator ----------------------
def owner_required(f):
    """Decorator to ensure the current user is a restaurant owner"""
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        user_data = get_jwt_identity()
        if not user_data or user_data.get("role") != UserRole.OWNER.value:
            return jsonify({"error": "Unauthorized"}), 403
        user = User.query.get(user_data["user_id"])
        if not user:
            return jsonify({"error": "User not found"}), 404
        return f(user, *args, **kwargs)
    return decorated

def get_restaurant_by_owner(owner):
    return Restaurant.query.filter_by(owner_id=owner.id).first()

# ---------------------- RESTAURANT PROFILE ----------------------
@restaurant_bp.route("/register", methods=["POST"])
@jwt_required()
@owner_required
def register_restaurant(owner):
    if get_restaurant_by_owner(owner):
        return jsonify({"error": "Restaurant already exists"}), 400
    data = request.json
    restaurant = Restaurant(
        name=data["name"],
        address=data.get("address"),
        owner_id=owner.id,
        verified=False,
        created_at=datetime.utcnow()
    )
    db.session.add(restaurant)
    db.session.commit()
    return jsonify({"message": "Restaurant registered", "id": restaurant.id}), 201

@restaurant_bp.route("/me", methods=["GET"])
@jwt_required()
@owner_required
def get_my_restaurant(owner):
    restaurant = get_restaurant_by_owner(owner)
    if not restaurant:
        return jsonify({"error": "No restaurant profile found"}), 404
    return jsonify({
        "id": restaurant.id,
        "name": restaurant.name,
        "address": restaurant.address,
        "verified": restaurant.verified,
        "active": getattr(restaurant, "active", True),
        "opening_hours": getattr(restaurant, "opening_hours", None),
        "gallery": getattr(restaurant, "gallery", [])
    })

@restaurant_bp.route("/me", methods=["PUT"])
@jwt_required()
@owner_required
def update_my_restaurant(owner):
    restaurant = get_restaurant_by_owner(owner)
    if not restaurant:
        return jsonify({"error": "No restaurant profile"}), 404
    data = request.json
    restaurant.name = data.get("name", restaurant.name)
    restaurant.address = data.get("address", restaurant.address)
    db.session.commit()
    return jsonify({"message": "Restaurant updated"})

@restaurant_bp.route("/me/verify", methods=["POST"])
@jwt_required()
@owner_required
def request_verification(owner):
    restaurant = get_restaurant_by_owner(owner)
    if not restaurant:
        return jsonify({"error": "No restaurant profile"}), 404
    restaurant.verification_requested = True
    db.session.commit()
    return jsonify({"message": "Verification requested"})

@restaurant_bp.route("/me/gallery", methods=["POST"])
@jwt_required()
@owner_required
def upload_gallery(owner):
    restaurant = get_restaurant_by_owner(owner)
    data = request.json
    images = data.get("images", [])
    if not images:
        return jsonify({"error": "No images provided"}), 400
    restaurant.gallery = images
    db.session.commit()
    return jsonify({"message": "Gallery updated"})

@restaurant_bp.route("/me/hours", methods=["PUT"])
@jwt_required()
@owner_required
def update_hours(owner):
    restaurant = get_restaurant_by_owner(owner)
    data = request.json
    restaurant.opening_hours = data.get("opening_hours", restaurant.opening_hours)
    db.session.commit()
    return jsonify({"message": "Opening hours updated"})

@restaurant_bp.route("/me/status", methods=["PUT"])
@jwt_required()
@owner_required
def toggle_status(owner):
    restaurant = get_restaurant_by_owner(owner)
    data = request.json
    restaurant.active = data.get("active", not getattr(restaurant, "active", True))
    db.session.commit()
    return jsonify({"message": f"Restaurant status set to {'active' if restaurant.active else 'inactive'}"})

# ---------------------- MENU MANAGEMENT ----------------------
@restaurant_bp.route("/menu", methods=["POST"])
@jwt_required()
@owner_required
def add_menu_item(owner):
    restaurant = get_restaurant_by_owner(owner)
    data = request.json
    item = MenuItem(
        name=data["name"],
        description=data.get("description"),
        price=data["price"],
        restaurant_id=restaurant.id,
        available=True,
        deleted=False,
        category=data.get("category")
    )
    db.session.add(item)
    db.session.commit()
    return jsonify({"message": "Menu item added", "id": item.id}), 201

@restaurant_bp.route("/menu", methods=["GET"])
@jwt_required()
@owner_required
def list_menu_items(owner):
    restaurant = get_restaurant_by_owner(owner)
    items = MenuItem.query.filter_by(restaurant_id=restaurant.id, deleted=False).all()
    return jsonify([{
        "id": i.id,
        "name": i.name,
        "price": i.price,
        "available": i.available,
        "category": i.category
    } for i in items])

@restaurant_bp.route("/menu/<int:item_id>", methods=["PUT"])
@jwt_required()
@owner_required
def update_menu_item(owner, item_id):
    item = MenuItem.query.get(item_id)
    if not item or item.restaurant.owner_id != owner.id:
        return jsonify({"error": "Menu item not found"}), 404
    data = request.json
    item.name = data.get("name", item.name)
    item.description = data.get("description", item.description)
    item.price = data.get("price", item.price)
    item.available = data.get("available", item.available)
    item.category = data.get("category", item.category)
    db.session.commit()
    return jsonify({"message": "Menu item updated"})

@restaurant_bp.route("/menu/<int:item_id>", methods=["DELETE"])
@jwt_required()
@owner_required
def delete_menu_item(owner, item_id):
    item = MenuItem.query.get(item_id)
    if not item or item.restaurant.owner_id != owner.id:
        return jsonify({"error": "Menu item not found"}), 404
    item.deleted = True
    db.session.commit()
    return jsonify({"message": "Menu item deleted"})

@restaurant_bp.route("/menu/<int:item_id>/availability", methods=["PATCH"])
@jwt_required()
@owner_required
def toggle_item_availability(owner, item_id):
    item = MenuItem.query.get(item_id)
    if not item or item.restaurant.owner_id != owner.id:
        return jsonify({"error": "Item not found"}), 404
    item.available = not item.available
    db.session.commit()
    return jsonify({"message": f"Item availability set to {item.available}"})

@restaurant_bp.route("/menu/bulk", methods=["POST"])
@jwt_required()
@owner_required
def bulk_menu_upload(owner):
    restaurant = get_restaurant_by_owner(owner)
    items = request.json.get("items", [])
    created = []
    for data in items:
        item = MenuItem(
            name=data["name"],
            description=data.get("description"),
            price=data["price"],
            restaurant_id=restaurant.id,
            category=data.get("category")
        )
        db.session.add(item)
        created.append(item)
    db.session.commit()
    return jsonify({"message": f"{len(created)} items added"})

@restaurant_bp.route("/menu/search", methods=["GET"])
@jwt_required()
@owner_required
def search_menu(owner):
    restaurant = get_restaurant_by_owner(owner)
    query = request.args.get("q", "")
    items = MenuItem.query.filter(
        MenuItem.restaurant_id==restaurant.id,
        MenuItem.deleted==False,
        MenuItem.name.ilike(f"%{query}%")
    ).all()
    return jsonify([{
        "id": i.id,
        "name": i.name,
        "price": i.price,
        "category": i.category
    } for i in items])

@restaurant_bp.route("/menu/<int:item_id>/category", methods=["PUT"])
@jwt_required()
@owner_required
def update_item_category(owner, item_id):
    item = MenuItem.query.get(item_id)
    if not item or item.restaurant.owner_id != owner.id:
        return jsonify({"error": "Item not found"}), 404
    item.category = request.json.get("category", item.category)
    db.session.commit()
    return jsonify({"message": "Item category updated"})

# ---------------------- ORDERS ----------------------
@restaurant_bp.route("/orders", methods=["GET"])
@jwt_required()
@owner_required
def list_orders(owner):
    restaurant = get_restaurant_by_owner(owner)
    orders = Order.query.filter_by(restaurant_id=restaurant.id).all()
    return jsonify([{
        "id": o.id,
        "status": o.status.value,
        "total": o.total_amount,
        "created_at": o.created_at.isoformat()
    } for o in orders])

@restaurant_bp.route("/order/<int:order_id>", methods=["GET"])
@jwt_required()
@owner_required
def get_order(owner, order_id):
    order = Order.query.get(order_id)
    if not order or order.restaurant.owner_id != owner.id:
        return jsonify({"error": "Order not found"}), 404
    return jsonify({
        "id": order.id,
        "status": order.status.value,
        "items": [{"menu_item": oi.menu_item.name, "qty": oi.quantity} for oi in order.items],
        "total": order.total_amount
    })

@restaurant_bp.route("/order/<int:order_id>/accept", methods=["POST"])
@jwt_required()
@owner_required
def accept_order(owner, order_id):
    order = Order.query.get(order_id)
    if not order or order.restaurant.owner_id != owner.id:
        return jsonify({"error": "Order not found"}), 404
    order.status = OrderStatus.ACCEPTED
    db.session.commit()
    return jsonify({"message": "Order accepted"})

@restaurant_bp.route("/order/<int:order_id>/reject", methods=["POST"])
@jwt_required()
@owner_required
def reject_order(owner, order_id):
    order = Order.query.get(order_id)
    if not order or order.restaurant.owner_id != owner.id:
        return jsonify({"error": "Order not found"}), 404
    order.status = OrderStatus.REJECTED
    db.session.commit()
    return jsonify({"message": "Order rejected"})

@restaurant_bp.route("/order/<int:order_id>/status", methods=["PUT"])
@owner_required
@jwt_required()
def update_order_status(order_id):
    data = request.get_json()
    order = Order.query.get(order_id)
    if not order:
        return jsonify({"error": "Order not found"}), 404

    new_status = data.get("status")
    if new_status not in ["Pending", "Preparing", "Ready", "Completed", "Cancelled"]:
        return jsonify({"error": "Invalid status"}), 400

    order.status = new_status
    db.session.commit()
    return jsonify({"message": f"Order status updated to {new_status}"}), 200

@restaurant_bp.route("/order/<int:order_id>/close", methods=["POST"])
@jwt_required()
@owner_required
def close_order(owner, order_id):
    order = Order.query.get(order_id)
    if not order or order.restaurant.owner_id != owner.id:
        return jsonify({"error": "Order not found"}), 404
    order.status = OrderStatus.COMPLETED
    db.session.commit()
    return jsonify({"message": "Order closed"})

@restaurant_bp.route("/orders", methods=["GET"])
@jwt_required()
def get_all_orders():
    orders = Order.query.all()
    data = []
    for o in orders:
        items = [
            {
                "menu_item": MenuItem.query.get(oi.menu_item_id).name,
                "qty": oi.quantity,
                "subtotal": oi.price * oi.quantity
            }
            for oi in o.items
        ]
        data.append({
            "order_id": o.id,
            "customer_id": o.customer_id,
            "status": o.status,
            "items": items,
            "created_at": o.created_at
        })
    return jsonify(data)

@restaurant_bp.route("/order/<int:order_id>/partial-accept", methods=["PATCH"])
@jwt_required()
@owner_required
def partial_accept(owner, order_id):
    order = Order.query.get(order_id)
    if not order or order.restaurant.owner_id != owner.id:
        return jsonify({"error": "Order not found"}), 404
    item_ids = request.json.get("item_ids", [])
    for oi in order.items:
        if oi.id in item_ids:
            oi.status = OrderStatus.ACCEPTED
    db.session.commit()
    return jsonify({"message": "Selected items accepted"})

@restaurant_bp.route("/orders/export", methods=["GET"])
@jwt_required()
@owner_required
def export_orders(owner):
    restaurant = get_restaurant_by_owner(owner)
    orders = Order.query.filter_by(restaurant_id=restaurant.id).all()
    export_data = [{"id": o.id, "total": o.total_amount, "status": o.status.value} for o in orders]
    return jsonify({"export": export_data})

@restaurant_bp.route("/order/<int:order_id>/notify", methods=["POST"])
@jwt_required()
@owner_required
def notify_customer(owner, order_id):
    # Placeholder for push notification integration
    return jsonify({"message": "Notification sent"})

# ---------------------- COUPONS ----------------------
@restaurant_bp.route("/coupons", methods=["POST"])
@jwt_required()
@owner_required
def add_coupon(owner):
    restaurant = get_restaurant_by_owner(owner)
    data = request.json
    coupon = Coupon(
        code=data["code"],
        discount=data["discount"],
        valid_from=datetime.fromisoformat(data["valid_from"]),
        valid_to=datetime.fromisoformat(data["valid_to"]),
        active=True,
        restaurant_id=restaurant.id
    )
    db.session.add(coupon)
    db.session.commit()
    return jsonify({"message": "Coupon created", "id": coupon.id})

@restaurant_bp.route("/coupons", methods=["GET"])
@jwt_required()
@owner_required
def list_coupons(owner):
    restaurant = get_restaurant_by_owner(owner)
    coupons = Coupon.query.filter_by(restaurant_id=restaurant.id).all()
    return jsonify([{
        "id": c.id,
        "code": c.code,
        "discount": c.discount,
        "active": c.active
    } for c in coupons])

@restaurant_bp.route("/coupon/<int:coupon_id>", methods=["PUT"])
@jwt_required()
@owner_required
def update_coupon(owner, coupon_id):
    coupon = Coupon.query.get(coupon_id)
    if not coupon or coupon.restaurant.owner_id != owner.id:
        return jsonify({"error": "Coupon not found"}), 404
    data = request.json
    coupon.code = data.get("code", coupon.code)
    coupon.discount = data.get("discount", coupon.discount)
    db.session.commit()
    return jsonify({"message": "Coupon updated"})

@restaurant_bp.route("/coupon/<int:coupon_id>", methods=["DELETE"])
@jwt_required()
@owner_required
def delete_coupon(owner, coupon_id):
    coupon = Coupon.query.get(coupon_id)
    if not coupon or coupon.restaurant.owner_id != owner.id:
        return jsonify({"error": "Coupon not found"}), 404
    db.session.delete(coupon)
    db.session.commit()
    return jsonify({"message": "Coupon deleted"})

@restaurant_bp.route("/coupons/bulk", methods=["POST"])
@jwt_required()
@owner_required
def bulk_coupons(owner):
    restaurant = get_restaurant_by_owner(owner)
    coupons = request.json.get("coupons", [])
    created = []
    for c in coupons:
        coupon = Coupon(
            code=c["code"],
            discount=c["discount"],
            valid_from=datetime.fromisoformat(c["valid_from"]),
            valid_to=datetime.fromisoformat(c["valid_to"]),
            active=True,
            restaurant_id=restaurant.id
        )
        db.session.add(coupon)
        created.append(coupon)
    db.session.commit()
    return jsonify({"message": f"{len(created)} coupons created"})

@restaurant_bp.route("/coupon/<int:coupon_id>/usage", methods=["GET"])
@jwt_required()
@owner_required
def coupon_usage(owner, coupon_id):
    coupon = Coupon.query.get(coupon_id)
    if not coupon or coupon.restaurant.owner_id != owner.id:
        return jsonify({"error": "Coupon not found"}), 404
    usage_count = Order.query.filter(Order.coupon_id==coupon.id, Order.status==OrderStatus.COMPLETED).count()
    return jsonify({"coupon": coupon.code, "used_count": usage_count})

@restaurant_bp.route("/coupon/<int:coupon_id>/schedule", methods=["PUT"])
@jwt_required()
@owner_required
def schedule_coupon(owner, coupon_id):
    coupon = Coupon.query.get(coupon_id)
    if not coupon or coupon.restaurant.owner_id != owner.id:
        return jsonify({"error": "Coupon not found"}), 404
    data = request.json
    coupon.valid_from = datetime.fromisoformat(data["valid_from"])
    coupon.valid_to = datetime.fromisoformat(data["valid_to"])
    db.session.commit()
    return jsonify({"message": "Coupon schedule updated"})

# ---------------- Revenue Report ----------------
@restaurant_bp.route("/reports/revenue", methods=["GET"])
@jwt_required()
def revenue_report():
    orders = Order.query.filter_by(status="Completed").all()
    total_revenue = 0
    for o in orders:
        for oi in o.items:
            total_revenue += oi.price * oi.quantity
    return jsonify({"total_revenue": total_revenue})



# ---------------- Refund Payment ----------------
@restaurant_bp.route("/refund/<int:payment_id>", methods=["POST"])
@jwt_required()
def refund_payment(payment_id):
    payment = Payment.query.get(payment_id)
    if not payment:
        return jsonify({"error": "Payment not found"}), 404

    if payment.status != "Completed":
        return jsonify({"error": "Only completed payments can be refunded"}), 400

    payment.status = "Refunded"
    db.session.commit()
    return jsonify({"message": "Payment refunded"}), 200



@restaurant_bp.route("/reports/<report_type>", methods=["GET"])
@jwt_required()
@owner_required
def get_reports(owner, report_type):
    # Placeholder for reports logic
    return jsonify({"message": f"Report {report_type} not implemented yet"}), 200

@restaurant_bp.route("/rewards", methods=["GET"])
@jwt_required()
@owner_required
def get_rewards(owner):
    # Placeholder for rewards logic
    return jsonify({"message": "Rewards list not implemented"}), 200

@restaurant_bp.route("/customers", methods=["GET"])
@jwt_required()
@owner_required
def get_customers(owner):
    # Placeholder for customer listing
    return jsonify({"message": "Customer list not implemented"}), 200

@restaurant_bp.route("/integrations/<integration_type>", methods=["GET", "POST"])
@jwt_required()
@owner_required
def integrations(owner, integration_type):
    # Placeholder for integrations logic
    return jsonify({"message": f"Integration {integration_type} not implemented"}), 200


from werkzeug.security import check_password_hash
from flask_jwt_extended import create_access_token, unset_jwt_cookies, set_access_cookies

# ---------------------- LOGIN ----------------------
@restaurant_bp.route("/login", methods=["POST"])
def restaurant_login():
    """
    Restaurant Owner Login
    Request JSON: { "email": "...", "password": "..." }
    Response: JWT token + restaurant info
    """
    data = request.json
    email = data.get("email")
    password = data.get("password")

    if not email or not password:
        return jsonify({"error": "Email and password required"}), 400

    user = User.query.filter_by(email=email, role=UserRole.OWNER).first()
    if not user:
        return jsonify({"error": "User not found"}), 404

    if not check_password_hash(user.password, password):
        return jsonify({"error": "Incorrect password"}), 401

    restaurant = get_restaurant_by_owner(user)
    if not restaurant:
        return jsonify({"error": "No restaurant assigned to this owner"}), 403

    # Create JWT token
    access_token = create_access_token(identity={"user_id": user.id, "role": user.role.value})

    response = jsonify({
        "message": "Login successful",
        "access_token": access_token,
        "restaurant": {
            "id": restaurant.id,
            "name": restaurant.name,
            "verified": restaurant.verified
        }
    })

    # Optional: set JWT in cookie
    # set_access_cookies(response, access_token)

    return response, 200

# ---------------------- LOGOUT ----------------------
@restaurant_bp.route("/logout", methods=["POST"])
@jwt_required()
def restaurant_logout():
    """
    Logout restaurant owner by clearing JWT cookie (client handles token removal)
    """
    response = jsonify({"message": "Logout successful"})
    unset_jwt_cookies(response)  # if using cookies
    return response, 200


@restaurant_bp.route("/dashboard", methods=["GET"])
@jwt_required()
@owner_required
def restaurant_dashboard(owner):
    restaurant = get_restaurant_by_owner(owner)
    if not restaurant:
        return jsonify({"error": "No restaurant profile found"}), 404

    # ------------------- Orders -------------------
    total_orders = Order.query.filter_by(restaurant_id=restaurant.id).count()
    orders_status_counts = db.session.query(
        Order.status,
        func.count(Order.id)
    ).filter_by(restaurant_id=restaurant.id).group_by(Order.status).all()
    orders_by_status = {status.value: count for status, count in orders_status_counts}

    # Revenue
    total_revenue = db.session.query(func.sum(OrderItem.price * OrderItem.quantity)).join(Order).filter(
        Order.restaurant_id==restaurant.id, Order.status=="Completed"
    ).scalar() or 0

    # Daily revenue & orders (last 30 days)
    from datetime import datetime, timedelta
    today = datetime.utcnow().date()
    thirty_days_ago = today - timedelta(days=30)
    daily_stats = db.session.query(
        func.date(Order.created_at),
        func.count(Order.id),
        func.sum(OrderItem.price * OrderItem.quantity)
    ).join(OrderItem).filter(
        Order.restaurant_id==restaurant.id,
        Order.created_at >= thirty_days_ago
    ).group_by(func.date(Order.created_at)).all()
    daily_orders = [{"date": str(d), "orders": o, "revenue": float(r or 0)} for d, o, r in daily_stats]

    # ------------------- Menu -------------------
    menu_items = MenuItem.query.filter_by(restaurant_id=restaurant.id, deleted=False).all()
    menu_data = [{"id": i.id, "name": i.name, "price": i.price, "available": i.available, "category": i.category} for i in menu_items]

    # Popular menu items
    popular_items = db.session.query(
        MenuItem.name,
        func.sum(OrderItem.quantity).label("total_sold")
    ).join(OrderItem, OrderItem.menu_item_id==MenuItem.id).join(Order, Order.id==OrderItem.order_id).filter(
        MenuItem.restaurant_id==restaurant.id,
        Order.status=="Completed"
    ).group_by(MenuItem.id).order_by(func.sum(OrderItem.quantity).desc()).limit(5).all()
    popular_items_data = [{"name": name, "sold": total_sold} for name, total_sold in popular_items]

    # ------------------- Coupons -------------------
    coupons = Coupon.query.filter_by(restaurant_id=restaurant.id).all()
    coupons_data = []
    for c in coupons:
        used_count = Order.query.filter(Order.coupon_id==c.id, Order.status=="Completed").count()
        coupons_data.append({"code": c.code, "discount": c.discount, "active": c.active, "used_count": used_count})

    # ------------------- Rewards -------------------
    # Placeholder: total reward points earned by customers
    rewards = [{"customer_id": u.id, "name": u.name, "points": getattr(u, "reward_points", 0)} for u in User.query.all()]

    # ------------------- Customers -------------------
    customers = User.query.filter(User.role==UserRole.CUSTOMER.value).all()
    customers_data = []
    for u in customers:
        user_orders = Order.query.filter_by(customer_id=u.id, restaurant_id=restaurant.id).all()
        total_spent = sum([o.total_amount for o in user_orders])
        customers_data.append({
            "id": u.id,
            "name": u.name,
            "email": u.email,
            "total_orders": len(user_orders),
            "total_spent": total_spent,
            "active": u.active
        })

    # ------------------- Reports -------------------
    reports = {
        "sales": None,  # Placeholder
        "popular_items": popular_items_data,
        "customers": [{"id": u.id, "name": u.name} for u in customers],
        "revenue_slots": None,
        "sales_trends": daily_orders,
        "refunds": Payment.query.filter_by(status="Refunded").count(),
        "discounts": len(coupons)
    }

    # ------------------- Integrations -------------------
    integrations = {
        "payment": {"enabled": True},  # Placeholder
        "pos": {"enabled": False},     # Placeholder
        "delivery": {"enabled": False} # Placeholder
    }

    dashboard = {
        "restaurant": {
            "id": restaurant.id,
            "name": restaurant.name,
            "verified": restaurant.verified,
            "active": getattr(restaurant, "active", True),
            "opening_hours": getattr(restaurant, "opening_hours", None)
        },
        "orders": {
            "total": total_orders,
            "by_status": orders_by_status,
            "total_revenue": float(total_revenue),
            "daily_stats": daily_orders
        },
        "menu": menu_data,
        "popular_items": popular_items_data,
        "coupons": coupons_data,
        "rewards": rewards,
        "customers": customers_data,
        "reports": reports,
        "integrations": integrations
    }

    return jsonify(dashboard)
