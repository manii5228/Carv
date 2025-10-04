# admin_routes.py
from flask import Blueprint, request, jsonify, send_file,current_app
from backend.models import db, User, Restaurant, Order, OrderItem, Payment, Review, Coupon, RewardTransaction
from sqlalchemy import func
import pandas as pd
from flask_jwt_extended import create_access_token,get_jwt, jwt_required
from datetime import datetime


admin_bp = Blueprint('admin', __name__, url_prefix='/admin')


# Simple login route
import jwt, datetime

@admin_bp.route('/login', methods=['POST'])
def admin_login_route():
    data = request.json
    email = data.get('email')
    password = data.get('password')

    admin_email = current_app.config.get("ADMIN_EMAIL", "admin@example.com")
    admin_password = current_app.config.get("ADMIN_PASSWORD", "admin123")

    if email == admin_email and password == admin_password:
        payload = {
            "email": email,
            "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)
        }
        token = jwt.encode(payload, current_app.config['SECRET_KEY'], algorithm="HS256")
        return jsonify({"access_token": token})

    return jsonify({"error": "Invalid credentials"}), 401

# Logout route
@admin_bp.route('/logout', methods=['POST'])
def admin_logout():
    # JWT logout is frontend’s responsibility (remove token)
    return jsonify({"message": "Admin logged out (token invalidated on client)."})


# Decorator to protect admin routes
def admin_required(fn):
    from functools import wraps
    @wraps(fn)
    @jwt_required()
    def wrapper(*args, **kwargs):
        claims = get_jwt()
        if claims.get("sub", {}).get("role") != "admin":
            return jsonify({"error": "Admins only!"}), 403
        return fn(*args, **kwargs)
    return wrapper

# ------------------ DASHBOARD SUMMARY ------------------
@admin_bp.route('/dashboard', methods=['GET'])
@admin_required
def dashboard_summary():
    total_restaurants = Restaurant.query.filter_by(is_deleted=False).count()
    total_users = User.query.filter_by(role='customer').count()
    total_orders = Order.query.count()
    total_revenue = db.session.query(func.sum(Payment.amount_paise)).filter(Payment.status=='success').scalar() or 0

    orders_by_status = db.session.query(Order.status, func.count(Order.id)).group_by(Order.status).all()
    orders_status_dict = {status.value: count for status, count in orders_by_status}

    return jsonify({
        "total_restaurants": total_restaurants,
        "total_users": total_users,
        "total_orders": total_orders,
        "total_revenue": total_revenue / 100.0,
        "orders_by_status": orders_status_dict
    })


# ------------------ RESTAURANT MANAGEMENT ------------------
@admin_bp.route('/restaurants', methods=['GET'])
@admin_required
def get_restaurants():
    # filters
    city = request.args.get('city')
    verified = request.args.get('verified')
    owner_id = request.args.get('owner_id')

    query = Restaurant.query.filter_by(is_deleted=False)
    if city:
        query = query.filter(Restaurant.address.ilike(f"%{city}%"))
    if verified in ['true', 'false']:
        query = query.filter_by(is_verified=verified=='true')
    if owner_id:
        query = query.filter_by(owner_id=owner_id)

    restaurants = query.all()
    data = []
    for r in restaurants:
        total_orders = r.orders.count()
        total_revenue = sum([o.total_amount_paise for o in r.orders if o.payment and o.payment.status.value=='SUCCESS']) / 100.0
        popular_items = db.session.query(OrderItem.name, func.sum(OrderItem.quantity).label('sold'))\
                          .join(Order)\
                          .filter(Order.restaurant_id==r.id)\
                          .group_by(OrderItem.name)\
                          .order_by(func.sum(OrderItem.quantity).desc())\
                          .limit(5).all()
        avg_rating = db.session.query(func.avg(Review.rating)).filter(Review.restaurant_id==r.id).scalar() or 0
        data.append({
            "id": r.id,
            "name": r.name,
            "owner": r.owner_id,
            "is_verified": r.is_verified,
            "total_orders": total_orders,
            "total_revenue": total_revenue,
            "popular_items": [{"name": item[0], "sold": item[1]} for item in popular_items],
            "average_rating": avg_rating
        })
    return jsonify(data)

@admin_bp.route('/restaurant/<int:restaurant_id>', methods=['GET'])
@admin_required
def get_single_restaurant(restaurant_id):
    r = Restaurant.query.get_or_404(restaurant_id)
    total_orders = r.orders.count()
    total_revenue = sum([o.total_amount_paise for o in r.orders if o.payment and o.payment.status.value=='SUCCESS']) / 100.0
    popular_items = db.session.query(OrderItem.name, func.sum(OrderItem.quantity).label('sold'))\
                      .join(Order)\
                      .filter(Order.restaurant_id==r.id)\
                      .group_by(OrderItem.name)\
                      .order_by(func.sum(OrderItem.quantity).desc())\
                      .limit(5).all()
    avg_rating = db.session.query(func.avg(Review.rating)).filter(Review.restaurant_id==r.id).scalar() or 0
    return jsonify({
        "id": r.id,
        "name": r.name,
        "owner": r.owner_id,
        "is_verified": r.is_verified,
        "total_orders": total_orders,
        "total_revenue": total_revenue,
        "popular_items": [{"name": item[0], "sold": item[1]} for item in popular_items],
        "average_rating": avg_rating
    })

@admin_bp.route('/restaurant/<int:restaurant_id>/verify', methods=['POST'])
@admin_required
def verify_restaurant(restaurant_id):
    r = Restaurant.query.get_or_404(restaurant_id)
    r.is_verified = True
    db.session.commit()
    return jsonify({"message": f"Restaurant {r.name} verified."})

@admin_bp.route('/restaurant/<int:restaurant_id>/block', methods=['POST'])
@admin_required
def block_restaurant(restaurant_id):
    r = Restaurant.query.get_or_404(restaurant_id)
    r.is_deleted = True
    db.session.commit()
    return jsonify({"message": f"Restaurant {r.name} blocked."})

@admin_bp.route('/restaurants/export', methods=['GET'])
@admin_required
def export_restaurants():
    restaurants = Restaurant.query.all()
    data = []
    for r in restaurants:
        total_orders = r.orders.count()
        total_revenue = sum([o.total_amount_paise for o in r.orders if o.payment and o.payment.status.value=='SUCCESS']) / 100.0
        avg_rating = db.session.query(func.avg(Review.rating)).filter(Review.restaurant_id==r.id).scalar() or 0
        data.append({
            "ID": r.id,
            "Name": r.name,
            "Owner ID": r.owner_id,
            "Verified": r.is_verified,
            "Deleted": r.is_deleted,
            "Total Orders": total_orders,
            "Total Revenue": total_revenue,
            "Average Rating": avg_rating
        })
    df = pd.DataFrame(data)
    filename = f"restaurants_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.xlsx"
    df.to_excel(filename, index=False)
    return send_file(filename, as_attachment=True)

@admin_bp.route('/restaurants/<int:restaurant_id>/unblock', methods=['POST'])
@admin_required
def unblock_restaurant(restaurant_id):
    r = Restaurant.query.get_or_404(restaurant_id)
    r.is_deleted = False
    db.session.commit()
    return jsonify({"message": f"Restaurant {r.name} unblocked."})

@admin_bp.route('/restaurants/<int:restaurant_id>', methods=['DELETE'])
@admin_required
def delete_restaurant_permanent(restaurant_id):
    r = Restaurant.query.get_or_404(restaurant_id)
    db.session.delete(r)
    db.session.commit()
    return jsonify({"message": f"Restaurant {r.name} permanently deleted."})

@admin_bp.route('/restaurants', methods=['POST'])
@admin_required
def add_restaurant():
    data = request.json
    r = Restaurant(
        name=data.get('name'),
        description=data.get('description'),
        latitude=data.get('latitude'),
        longitude=data.get('longitude'),
        address=data.get('address'),
        owner_id=data.get('owner_id'),
        is_verified=data.get('is_verified', False)
    )
    db.session.add(r)
    db.session.commit()
    return jsonify({"message": f"Restaurant {r.name} added.", "id": r.id})

@admin_bp.route('/restaurants/<int:restaurant_id>', methods=['PUT'])
@admin_required
def edit_restaurant(restaurant_id):
    r = Restaurant.query.get_or_404(restaurant_id)
    data = request.json
    for key in ['name', 'description', 'latitude', 'longitude', 'address', 'owner_id', 'is_verified']:
        if key in data:
            setattr(r, key, data[key])
    db.session.commit()
    return jsonify({"message": f"Restaurant {r.name} updated."})


# ------------------ USER MANAGEMENT ------------------
@admin_bp.route('/users', methods=['GET'])
@admin_required
def get_users():
    users = User.query.filter_by(role='customer').all()
    data = []
    for u in users:
        total_orders = u.orders.count()
        total_spent = sum([o.total_amount_paise for o in u.orders if o.payment and o.payment.status.value=='SUCCESS']) / 100.0
        data.append({
            "id": u.id,
            "name": u.name,
            "email": u.email,
            "points": u.points,
            "total_orders": total_orders,
            "total_spent": total_spent
        })
    return jsonify(data)

@admin_bp.route('/user/<int:user_id>/block', methods=['POST'])
@admin_required
def block_user(user_id):
    user = User.query.get_or_404(user_id)
    user.is_deleted = True
    db.session.commit()
    return jsonify({"message": f"User {user.name} blocked."})

@admin_bp.route('/users/export', methods=['GET'])
@admin_required
def export_users():
    users = User.query.filter_by(role='customer').all()
    data = []
    for u in users:
        total_orders = u.orders.count()
        total_spent = sum([o.total_amount_paise for o in u.orders if o.payment and o.payment.status.value=='SUCCESS']) / 100.0
        data.append({
            "ID": u.id,
            "Name": u.name,
            "Email": u.email,
            "Points": u.points,
            "Total Orders": total_orders,
            "Total Spent": total_spent
        })
    df = pd.DataFrame(data)
    filename = f"users_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.xlsx"
    df.to_excel(filename, index=False)
    return send_file(filename, as_attachment=True)

@admin_bp.route('/users/<int:user_id>/unblock', methods=['POST'])
@admin_required
def unblock_user(user_id):
    u = User.query.get_or_404(user_id)
    u.is_deleted = False
    db.session.commit()
    return jsonify({"message": f"User {u.name} unblocked."})

@admin_bp.route('/users/<int:user_id>', methods=['PUT'])
@admin_required
def edit_user(user_id):
    u = User.query.get_or_404(user_id)
    data = request.json
    for key in ['name', 'email', 'points']:
        if key in data:
            setattr(u, key, data[key])
    db.session.commit()
    return jsonify({"message": f"User {u.name} updated."})
# ------------------ ORDER & PAYMENT MANAGEMENT ------------------
@admin_bp.route('/orders', methods=['GET'])
@admin_required
def get_orders():
    status_filter = request.args.get('status')
    restaurant_id = request.args.get('restaurant_id')
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')

    query = Order.query
    if status_filter:
        query = query.filter_by(status=status_filter)
    if restaurant_id:
        query = query.filter_by(restaurant_id=restaurant_id)
    if start_date:
        query = query.filter(Order.scheduled_time >= datetime.fromisoformat(start_date))
    if end_date:
        query = query.filter(Order.scheduled_time <= datetime.fromisoformat(end_date))

    orders = query.all()
    data = []
    for o in orders:
        data.append({
            "id": o.id,
            "user_id": o.user_id,
            "restaurant_id": o.restaurant_id,
            "status": o.status.value,
            "scheduled_time": o.scheduled_time,
            "total_amount": o.total_amount_display(),
            "payment_status": o.payment.status.value if o.payment else "N/A"
        })
    return jsonify(data)

@admin_bp.route('/orders/export', methods=['GET'])
@admin_required
def export_orders():
    orders = Order.query.all()
    data = []
    for o in orders:
        data.append({
            "ID": o.id,
            "User ID": o.user_id,
            "Restaurant ID": o.restaurant_id,
            "Status": o.status.value,
            "Scheduled Time": o.scheduled_time,
            "Total Amount": o.total_amount_display(),
            "Payment Status": o.payment.status.value if o.payment else "N/A"
        })
    df = pd.DataFrame(data)
    filename = f"orders_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.xlsx"
    df.to_excel(filename, index=False)
    return send_file(filename, as_attachment=True)

@admin_bp.route('/orders/<int:order_id>/cancel', methods=['POST'])
@admin_required
def admin_cancel_order(order_id):
    o = Order.query.get_or_404(order_id)
    o.status = "CANCELLED"
    db.session.commit()
    return jsonify({"message": f"Order {o.id} cancelled by admin."})

@admin_bp.route('/orders/<int:order_id>/reassign', methods=['POST'])
@admin_required
def admin_reassign_order(order_id):
    o = Order.query.get_or_404(order_id)
    data = request.json
    new_restaurant_id = data.get("restaurant_id")
    if new_restaurant_id:
        o.restaurant_id = new_restaurant_id
        db.session.commit()
        return jsonify({"message": f"Order {o.id} reassigned to restaurant {new_restaurant_id}."})
    return jsonify({"error": "restaurant_id required"}), 400

@admin_bp.route('/orders/<int:order_id>/refund', methods=['POST'])
@admin_required
def admin_refund_order(order_id):
    o = Order.query.get_or_404(order_id)
    if not o.payment:
        return jsonify({"error": "Order has no payment."}), 400
    o.payment.status = "FAILED"
    db.session.commit()
    return jsonify({"message": f"Order {o.id} refunded by admin."})
# ------------------ COUPON MANAGEMENT ------------------
@admin_bp.route('/coupons', methods=['GET'])
@admin_required
def get_coupons():
    coupons = Coupon.query.all()
    data = []
    for c in coupons:
        data.append({
            "id": c.id,
            "code": c.code,
            "discount_percent": c.discount_percent,
            "discount_paise": c.discount_paise,
            "valid_from": c.valid_from,
            "valid_to": c.valid_to,
            "usage_count": c.usage_count,
            "usage_limit": c.usage_limit,
            "is_active": c.is_active
        })
    return jsonify(data)

@admin_bp.route('/coupon/<int:coupon_id>/toggle', methods=['POST'])
@admin_required
def toggle_coupon(coupon_id):
    coupon = Coupon.query.get_or_404(coupon_id)
    coupon.is_active = not coupon.is_active
    db.session.commit()
    return jsonify({"message": f"Coupon {coupon.code} active status set to {coupon.is_active}"})

@admin_bp.route('/coupons', methods=['POST'])
@admin_required
def create_coupon():
    data = request.json
    c = Coupon(
        code=data['code'],
        discount_percent=data.get('discount_percent'),
        discount_paise=data.get('discount_paise'),
        valid_from=data.get('valid_from'),
        valid_to=data.get('valid_to'),
        usage_limit=data.get('usage_limit'),
        min_order_amount_paise=data.get('min_order_amount_paise',0),
        is_active=data.get('is_active', True)
    )
    db.session.add(c)
    db.session.commit()
    return jsonify({"message": f"Coupon {c.code} created.", "id": c.id})

@admin_bp.route('/coupons/<int:coupon_id>', methods=['PUT'])
@admin_required
def edit_coupon(coupon_id):
    c = Coupon.query.get_or_404(coupon_id)
    data = request.json
    for key in ['code', 'discount_percent', 'discount_paise', 'valid_from', 'valid_to', 'usage_limit', 'min_order_amount_paise', 'is_active']:
        if key in data:
            setattr(c, key, data[key])
    db.session.commit()
    return jsonify({"message": f"Coupon {c.code} updated."})

@admin_bp.route('/coupons/<int:coupon_id>', methods=['DELETE'])
@admin_required
def delete_coupon(coupon_id):
    c = Coupon.query.get_or_404(coupon_id)
    db.session.delete(c)
    db.session.commit()
    return jsonify({"message": f"Coupon {c.code} deleted."})

# ------------------ REVIEW MANAGEMENT ------------------
@admin_bp.route('/reviews', methods=['GET'])
@admin_required
def get_reviews():
    restaurant_id = request.args.get('restaurant_id')
    min_rating = request.args.get('min_rating')
    query = Review.query
    if restaurant_id:
        query = query.filter_by(restaurant_id=restaurant_id)
    if min_rating:
        query = query.filter(Review.rating >= int(min_rating))
    reviews = query.all()
    data = []
    for r in reviews:
        data.append({
            "id": r.id,
            "user_id": r.user_id,
            "restaurant_id": r.restaurant_id,
            "rating": r.rating,
            "comment": r.comment
        })
    return jsonify(data)

@admin_bp.route('/reviews/<int:review_id>', methods=['DELETE'])
@admin_required
def delete_review(review_id):
    r = Review.query.get_or_404(review_id)
    db.session.delete(r)
    db.session.commit()
    return jsonify({"message": f"Review {review_id} deleted."})
# ------------------ ADDITIONAL ANALYTICS ROUTES ------------------
@admin_bp.route('/analytics/revenue_by_day', methods=['GET'])
@admin_required
def revenue_by_day():
    results = db.session.query(func.date(Order.scheduled_time), func.sum(Payment.amount_paise))\
             .join(Payment)\
             .filter(Payment.status=='SUCCESS')\
             .group_by(func.date(Order.scheduled_time))\
             .all()
    return jsonify([{ "date": str(row[0]), "revenue": row[1]/100.0 } for row in results])

@admin_bp.route('/analytics/top_restaurants', methods=['GET'])
@admin_required
def top_restaurants():
    limit = int(request.args.get('limit', 10))
    results = db.session.query(Restaurant.name, func.sum(Order.total_amount_paise))\
             .join(Order)\
             .join(Payment)\
             .filter(Payment.status=='SUCCESS')\
             .group_by(Restaurant.id)\
             .order_by(func.sum(Order.total_amount_paise).desc())\
             .limit(limit).all()
    return jsonify([{ "restaurant": row[0], "revenue": row[1]/100.0 } for row in results])
