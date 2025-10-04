# ---------------------------- MODELS.PY — FINAL ----------------------------
from .extensions import db
from datetime import datetime
from sqlalchemy import CheckConstraint, Index
import enum, random, hashlib


# ---------------------------- MIXINS ----------------------------
class TimestampMixin:
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow,
                           onupdate=datetime.utcnow, nullable=False)


class SoftDeleteMixin:
    is_deleted = db.Column(db.Boolean, default=False, nullable=False)


# ---------------------------- ENUMS ----------------------------
class UserRole(enum.Enum):
    CUSTOMER = "customer"
    OWNER = "owner"
    ADMIN = "admin"


class OrderStatus(enum.Enum):
    SCHEDULED = "scheduled"
    PREPARING = "preparing"
    READY = "ready"
    COMPLETED = "completed"
    CANCELLED = "cancelled"


class PaymentStatus(enum.Enum):
    PENDING = "pending"
    SUCCESS = "success"
    FAILED = "failed"


# ---------------------------- ASSOCIATIONS ----------------------------
favorites = db.Table(
    "favorites",
    db.Column("user_id", db.Integer, db.ForeignKey("user.id")),
    db.Column("restaurant_id", db.Integer, db.ForeignKey("restaurant.id"))
)


# ---------------------------- USER ----------------------------
class User(db.Model, TimestampMixin):
    __tablename__ = "user"

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    name = db.Column(db.String(150))
    role = db.Column(db.Enum(UserRole), default=UserRole.CUSTOMER, nullable=False)
    points = db.Column(db.Integer, default=0, nullable=False)

    # Relationships
    orders = db.relationship("Order", back_populates="user", lazy="dynamic")
    favorites = db.relationship("Restaurant", secondary=favorites, backref="liked_by")
    reviews = db.relationship("Review", backref="user", lazy="dynamic")
    rewards = db.relationship("RewardTransaction", backref="user", lazy="dynamic")
    addresses = db.relationship("Address", backref="user", lazy="dynamic")
    cart_items = db.relationship("CartItem", backref="user", lazy="dynamic")


# ---------------------------- RESTAURANT ----------------------------
class Restaurant(db.Model, TimestampMixin, SoftDeleteMixin):
    __tablename__ = "restaurant"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False, index=True)
    description = db.Column(db.Text)
    latitude = db.Column(db.Float, nullable=False)
    longitude = db.Column(db.Float, nullable=False)
    address = db.Column(db.String(255))
    owner_id = db.Column(db.Integer, db.ForeignKey("user.id", ondelete="SET NULL"))
    is_verified = db.Column(db.Boolean, default=False, nullable=False)

    # Relationships
    menu_items = db.relationship("MenuItem", back_populates="restaurant", lazy="dynamic")
    orders = db.relationship("Order", back_populates="restaurant", lazy="dynamic")
    reviews = db.relationship("Review", backref="restaurant", lazy="dynamic")

    __table_args__ = (
        Index("ix_restaurant_lat_lng", "latitude", "longitude"),
    )


# ---------------------------- MENU ITEM ----------------------------
class MenuItem(db.Model, TimestampMixin):
    __tablename__ = "menu_item"

    id = db.Column(db.Integer, primary_key=True)
    restaurant_id = db.Column(db.Integer, db.ForeignKey("restaurant.id", ondelete="CASCADE"), nullable=False, index=True)
    name = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    price_in_paise = db.Column(db.Integer, nullable=False)  # stored in paise
    currency = db.Column(db.String(3), default="INR", nullable=False)
    available = db.Column(db.Boolean, default=True, nullable=False)

    restaurant = db.relationship("Restaurant", back_populates="menu_items")
    cart_items = db.relationship("CartItem", back_populates="menu_item", lazy="dynamic")

    def price_display(self):
        return float(self.price_in_paise) / 100.0


# ---------------------------- ORDER ----------------------------
class Order(db.Model, TimestampMixin):
    __tablename__ = "order"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id", ondelete="SET NULL"), nullable=False, index=True)
    restaurant_id = db.Column(db.Integer, db.ForeignKey("restaurant.id", ondelete="SET NULL"), nullable=False, index=True)
    status = db.Column(db.Enum(OrderStatus), default=OrderStatus.SCHEDULED, nullable=False, index=True)
    scheduled_time = db.Column(db.DateTime, nullable=False, index=True)
    total_amount_paise = db.Column(db.Integer, nullable=False)
    otp_code = db.Column(db.String(6), nullable=True)
    qr_code_data = db.Column(db.String(256), nullable=True)
    verified_at = db.Column(db.DateTime, nullable=True)
    coupon_id = db.Column(db.Integer, db.ForeignKey("coupon.id", ondelete="SET NULL"))  # ✅ link coupon


    user = db.relationship("User", back_populates="orders")
    restaurant = db.relationship("Restaurant", back_populates="orders")
    items = db.relationship("OrderItem", back_populates="order", cascade="all, delete-orphan", lazy="joined")
    payment = db.relationship("Payment", back_populates="order", uselist=False, cascade="all, delete-orphan")
    rewards = db.relationship("RewardTransaction", backref="order", lazy="dynamic")  # ✅ backref added

    __table_args__ = (
        Index("ix_order_restaurant_scheduled", "restaurant_id", "scheduled_time"),
    )

    def generate_otp(self):
        self.otp_code = f"{random.randint(100000, 999999)}"
        return self.otp_code

    def generate_qr_payload(self, secret_key):
        payload = f"{self.id}-{self.otp_code}-{secret_key}"
        self.qr_code_data = hashlib.sha256(payload.encode()).hexdigest()
        return self.qr_code_data

    def total_amount_display(self):
        return float(self.total_amount_paise) / 100.0


# ---------------------------- ORDER ITEM ----------------------------
class OrderItem(db.Model):
    __tablename__ = "order_item"

    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey("order.id", ondelete="CASCADE"), nullable=False, index=True)
    menu_item_id = db.Column(db.Integer, db.ForeignKey("menu_item.id", ondelete="SET NULL"))
    name = db.Column(db.String(200), nullable=False)
    quantity = db.Column(db.Integer, default=1, nullable=False)
    price_in_paise = db.Column(db.Integer, nullable=False)

    order = db.relationship("Order", back_populates="items")


# ---------------------------- PAYMENT ----------------------------
class Payment(db.Model, TimestampMixin):
    __tablename__ = "payment"

    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey("order.id", ondelete="CASCADE"), nullable=False, unique=True)
    amount_paise = db.Column(db.Integer, nullable=False)
    method = db.Column(db.String(50))
    status = db.Column(db.Enum(PaymentStatus), default=PaymentStatus.PENDING, nullable=False)
    provider_name = db.Column(db.String(50))  # ✅ added provider name
    transaction_id = db.Column(db.String(255))
    provider_payload = db.Column(db.JSON, nullable=True)

    order = db.relationship("Order", back_populates="payment")


# ---------------------------- COUPON ----------------------------
class Coupon(db.Model):
    __tablename__ = "coupon"

    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(64), unique=True, nullable=False, index=True)
    discount_percent = db.Column(db.Integer, nullable=True)
    discount_paise = db.Column(db.Integer, nullable=True)
    valid_from = db.Column(db.DateTime, default=datetime.utcnow)
    valid_to = db.Column(db.DateTime, nullable=True)
    usage_limit = db.Column(db.Integer, nullable=True)
    usage_count = db.Column(db.Integer, default=0, nullable=False)
    min_order_amount_paise = db.Column(db.Integer, default=0)
    is_active = db.Column(db.Boolean, default=True, nullable=False)

    __table_args__ = (
        CheckConstraint("(discount_percent IS NOT NULL) OR (discount_paise IS NOT NULL)", name="coupon_discount_check"),
    )


# ---------------------------- REVIEW ----------------------------
class Review(db.Model, TimestampMixin):
    __tablename__ = "review"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id", ondelete="SET NULL"), nullable=False)
    restaurant_id = db.Column(db.Integer, db.ForeignKey("restaurant.id", ondelete="CASCADE"), nullable=False)
    rating = db.Column(db.Integer, nullable=False)
    comment = db.Column(db.Text)
    attachments = db.Column(db.JSON, nullable=True)  # ✅ optional review images/files


    __table_args__ = (
        CheckConstraint('rating >= 1 AND rating <= 5', name="rating_check"),
    )


# ---------------------------- REWARD TRANSACTION ----------------------------
class RewardTransaction(db.Model, TimestampMixin):
    __tablename__ = "reward_transaction"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id", ondelete="CASCADE"), nullable=False, index=True)
    points = db.Column(db.Integer, nullable=False)
    type = db.Column(db.String(20), nullable=False)  # 'earn' or 'redeem'
    order_id = db.Column(db.Integer, db.ForeignKey("order.id"), nullable=True)


# ---------------------------- ADDRESS ----------------------------
class Address(db.Model, TimestampMixin):
    __tablename__ = "address"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id", ondelete="CASCADE"), nullable=False, index=True)
    street = db.Column(db.String(255))
    city = db.Column(db.String(100))
    state = db.Column(db.String(100))
    zipcode = db.Column(db.String(20))
    country = db.Column(db.String(100))
    is_default = db.Column(db.Boolean, default=False)


# ---------------------------- CART (before order placed) ----------------------------
class CartItem(db.Model, TimestampMixin):
    __tablename__ = "cart_item"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id", ondelete="CASCADE"), nullable=False)
    cart_id = db.Column(db.Integer, db.ForeignKey("cart.id", ondelete="CASCADE"), nullable=False)
    menu_item_id = db.Column(db.Integer, db.ForeignKey("menu_item.id", ondelete="CASCADE"), nullable=False)
    quantity = db.Column(db.Integer, default=1, nullable=False)
    cart_id = db.Column(db.Integer, db.ForeignKey("cart.id", ondelete="CASCADE"), nullable=False)  # ✅ FIXED


    menu_item = db.relationship("MenuItem", back_populates="cart_items")
    cart = db.relationship("Cart", back_populates="items")
    
class Cart(db.Model, TimestampMixin):
    __tablename__ = "cart"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id", ondelete="CASCADE"), nullable=False)
    items = db.relationship("CartItem", back_populates="cart", cascade="all, delete-orphan")
