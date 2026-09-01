"""
Islamabad Restaurant & Cafe — Full Restaurant System
Flask + PostgreSQL + Cloudflare-ready
v6  —  fully secured
"""
import os, io, json, datetime, qrcode, sqlite3, csv, hashlib, hmac, secrets, time
import requests as http_requests
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from flask import (Flask, render_template, request, jsonify,
                   send_file, redirect, url_for, session, make_response, abort)
from flask_sqlalchemy import SQLAlchemy
from flask_compress import Compress

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

app = Flask(__name__)

def _persistent_dev_secret():
    """Fallback SECRET_KEY when SECRET_KEY isn't set via env — random per
    install, persisted locally (gitignored) so sessions survive restarts.
    Never rely on this in production; set the SECRET_KEY env var instead."""
    path = os.path.join(BASE_DIR, "instance", ".secret_key")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if os.path.exists(path):
        with open(path) as f:
            return f.read().strip()
    key = secrets.token_hex(32)
    with open(path, "w") as f:
        f.write(key)
    return key

_secret_key = os.environ.get("SECRET_KEY")
if not _secret_key:
    print("[WARN] SECRET_KEY env var not set — using a random per-install key. "
          "Set SECRET_KEY before deploying to production.")
    _secret_key = _persistent_dev_secret()

_admin_pin = os.environ.get("ADMIN_PIN")
if not _admin_pin:
    print("[WARN] ADMIN_PIN env var not set — defaulting to '1234'. "
          "Set a real ADMIN_PIN before going live; this PIN can void/modify bills.")
    _admin_pin = "1234"

_database_url = os.environ.get("DATABASE_URL")
if not _database_url:
    raise RuntimeError(
        "DATABASE_URL env var not set. Set it to the Postgres connection "
        "string, e.g. postgresql://user:pass@localhost:5432/dbname"
    )

app.config.update(
    SQLALCHEMY_DATABASE_URI = _database_url,
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
    SECRET_KEY=_secret_key,
    SESSION_COOKIE_NAME="maibistro_staff",
    SESSION_COOKIE_DOMAIN=None,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=os.environ.get("SESSION_COOKIE_SECURE", "true").lower() == "true",
    PERMANENT_SESSION_LIFETIME=datetime.timedelta(hours=12),
    COMPRESS_MIMETYPES=["text/html","text/css","application/json",
                        "application/javascript","image/svg+xml"],
    COMPRESS_LEVEL=6, COMPRESS_MIN_SIZE=512,
    ADMIN_PIN=_admin_pin,
    HITPAY_API_KEY=os.environ.get("HITPAY_API_KEY", ""),
    HITPAY_SALT=os.environ.get("HITPAY_SALT", ""),
    HITPAY_SANDBOX=os.environ.get("HITPAY_SANDBOX", "true").lower() == "true",
)
db = SQLAlchemy(app)
Compress(app)

# Public site URL — used to build absolute links (QR codes, payment gateway
# redirect/webhook URLs, OAuth callback) that must resolve from outside the
# server. Override with SITE_URL env var if deploying under a different domain.
SITE_URL = os.environ.get("SITE_URL", "https://isbrestaurant.com").rstrip("/")

RESTAURANT = {
    "name": "Islamabad Restaurant & Cafe",
    "tagline": "A True Taste of Pakistan",
    "address": "No. 128, Jalan Sultan Azlan Shah, 51200 Kuala Lumpur, Wilayah Persekutuan",
    "phone": "+60 1X-XXX XXXX",
    "est": "2023",
    "primary": "#C65A1E",
}

# ════════════════════════════════════════════
#  MODELS
# ════════════════════════════════════════════

class Category(db.Model):
    id         = db.Column(db.Integer, primary_key=True)
    name       = db.Column(db.String(60), unique=True, nullable=False)
    image_url  = db.Column(db.String(255), default="")
    sort_order = db.Column(db.Integer, default=0)

class StaffUser(db.Model):
    """Staff accounts for POS/Kitchen/Admin login."""
    id           = db.Column(db.Integer, primary_key=True)
    username     = db.Column(db.String(40), unique=True, nullable=False)
    password_hash= db.Column(db.String(255), nullable=False)
    role         = db.Column(db.String(20), default="staff")  # admin / manager / staff
    active       = db.Column(db.Boolean, default=True)
    created_at   = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    last_login   = db.Column(db.DateTime, nullable=True)

    def set_password(self, pw):
        self.password_hash = generate_password_hash(pw)

    def check_password(self, pw):
        stored = self.password_hash or ""
        if stored.startswith(("pbkdf2:", "scrypt:")):
            return check_password_hash(stored, pw)
        # Legacy unsalted-SHA256 hash from before the security upgrade —
        # verify once against the old scheme, then transparently re-hash
        # with a salted algorithm so it's never stored as SHA256 again.
        if stored and hmac.compare_digest(stored, hashlib.sha256(pw.encode()).hexdigest()):
            self.set_password(pw)
            db.session.commit()
            return True
        return False

class IPWhitelist(db.Model):
    """Allowed IPs for admin/POS/kitchen — empty = allow all."""
    id         = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(45), unique=True, nullable=False)
    label      = db.Column(db.String(60), default="")
    added_at   = db.Column(db.DateTime, default=datetime.datetime.utcnow)

class LoginLog(db.Model):
    """Audit trail for all login attempts."""
    id         = db.Column(db.Integer, primary_key=True)
    username   = db.Column(db.String(40), default="")
    ip_address = db.Column(db.String(45), default="")
    success    = db.Column(db.Boolean, default=False)
    path       = db.Column(db.String(80), default="")
    at         = db.Column(db.DateTime, default=datetime.datetime.utcnow)

class FailedAttempt(db.Model):
    """Track failed logins per IP for rate limiting."""
    id         = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(45), nullable=False)
    count      = db.Column(db.Integer, default=1)
    locked_until = db.Column(db.DateTime, nullable=True)
    updated_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

class SiteSetting(db.Model):
    key   = db.Column(db.String(80), primary_key=True)
    value = db.Column(db.Text, default="")

class Waiter(db.Model):
    id     = db.Column(db.Integer, primary_key=True)
    name   = db.Column(db.String(80), nullable=False)
    pin    = db.Column(db.String(10), default="")   # optional 4-digit PIN
    active = db.Column(db.Boolean, default=True)

class MenuItem(db.Model):
    id          = db.Column(db.Integer, primary_key=True)
    category    = db.Column(db.String(40), nullable=False)
    name        = db.Column(db.String(120), nullable=False)
    price_full  = db.Column(db.Float, default=0)
    price_half  = db.Column(db.Float, default=0)
    description = db.Column(db.Text, default="")
    image_url   = db.Column(db.String(255), default="")
    images_json = db.Column(db.Text, default="[]")
    rating      = db.Column(db.Float, default=4.5)
    available   = db.Column(db.Boolean, default=True)
    sort_order  = db.Column(db.Integer, default=0)

    @property
    def images(self):
        try:
            imgs = json.loads(self.images_json or "[]")
        except Exception:
            imgs = []
        return imgs if imgs else ([self.image_url] if self.image_url else [])

class RestaurantTable(db.Model):
    id     = db.Column(db.Integer, primary_key=True)
    number = db.Column(db.Integer, unique=True, nullable=False)
    label  = db.Column(db.String(40))
    status = db.Column(db.String(20), default="free")
    token  = db.Column(db.String(32), default="")

class AddOn(db.Model):
    id        = db.Column(db.Integer, primary_key=True)
    name      = db.Column(db.String(80), nullable=False)
    price     = db.Column(db.Float, default=0)
    image_url = db.Column(db.String(255), default="")
    available = db.Column(db.Boolean, default=True)

class Order(db.Model):
    id                = db.Column(db.Integer, primary_key=True)
    order_no          = db.Column(db.String(20), unique=True)
    order_type        = db.Column(db.String(20), default="dine_in")
    table_number      = db.Column(db.Integer, nullable=True)
    customer_name     = db.Column(db.String(120), default="")
    customer_phone    = db.Column(db.String(40), default="")
    delivery_address  = db.Column(db.String(255), default="")
    waiter_name       = db.Column(db.String(60), default="")
    status            = db.Column(db.String(20), default="pending")
    payment_status    = db.Column(db.String(20), default="unpaid")
    payment_method    = db.Column(db.String(20), default="")
    subtotal          = db.Column(db.Float, default=0)
    tax               = db.Column(db.Float, default=0)
    service_charge    = db.Column(db.Float, default=0)
    discount_type     = db.Column(db.String(20), default="none")
    discount_value    = db.Column(db.Float, default=0)
    discount_amount   = db.Column(db.Float, default=0)
    total             = db.Column(db.Float, default=0)
    customer_paid     = db.Column(db.Float, default=0)
    change_due        = db.Column(db.Float, default=0)
    customer_id       = db.Column(db.Integer, nullable=True)
    source            = db.Column(db.String(20), default="online")
    platform_order_id = db.Column(db.String(80), default="")
    token_no          = db.Column(db.String(10), default="")   # T001, T002...
    takeaway_no       = db.Column(db.Integer, nullable=True)   # 1-10 takeaway queue
    master_key_used   = db.Column(db.Boolean, default=False)
    notes             = db.Column(db.String(255), default="")
    created_at        = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    items = db.relationship("OrderItem", backref="order", cascade="all, delete-orphan")

class OrderItem(db.Model):
    id           = db.Column(db.Integer, primary_key=True)
    order_id     = db.Column(db.Integer, db.ForeignKey("order.id"))
    menu_item_id = db.Column(db.Integer, db.ForeignKey("menu_item.id"), nullable=True)
    name         = db.Column(db.String(120))
    size         = db.Column(db.String(10), default="full")
    qty          = db.Column(db.Integer, default=1)
    unit_price   = db.Column(db.Float, default=0)
    notes        = db.Column(db.String(255), default="")
    addons_json  = db.Column(db.Text, default="[]")

    @property
    def addons(self):
        try: return json.loads(self.addons_json or "[]")
        except Exception: return []

    @property
    def addons_total(self):
        return sum(a.get("price", 0) for a in self.addons)

    @property
    def line_total(self):
        return round((self.unit_price + self.addons_total) * self.qty, 2)


class Reservation(db.Model):
    id           = db.Column(db.Integer, primary_key=True)
    name         = db.Column(db.String(120), nullable=False)
    phone        = db.Column(db.String(40), nullable=False)
    email        = db.Column(db.String(120), default="")
    table_number = db.Column(db.Integer, nullable=True)
    guests       = db.Column(db.Integer, default=2)
    date         = db.Column(db.Date, nullable=False)
    time         = db.Column(db.String(10), nullable=False)
    notes        = db.Column(db.Text, default="")
    status       = db.Column(db.String(20), default="pending")
    created_at   = db.Column(db.DateTime, default=datetime.datetime.utcnow)


class Customer(db.Model):
    id            = db.Column(db.Integer, primary_key=True)
    name          = db.Column(db.String(120), nullable=False)
    email         = db.Column(db.String(120), unique=True, nullable=False)
    phone         = db.Column(db.String(40), default="")
    address       = db.Column(db.String(255), default="")
    password_hash = db.Column(db.String(255), nullable=False)
    active        = db.Column(db.Boolean, default=True)
    email_verified   = db.Column(db.Boolean, default=False)
    verify_token      = db.Column(db.String(64), default="")
    verify_token_sent = db.Column(db.DateTime, nullable=True)
    created_at    = db.Column(db.DateTime, default=datetime.datetime.utcnow)

    def set_password(self, pw):
        self.password_hash = generate_password_hash(pw)
    def check_password(self, pw):
        stored = self.password_hash or ""
        if stored.startswith(("pbkdf2:", "scrypt:")):
            return check_password_hash(stored, pw)
        if stored and hmac.compare_digest(stored, hashlib.sha256(pw.encode()).hexdigest()):
            self.set_password(pw)
            db.session.commit()
            return True
        return False


# ════════════════════════════════════════════
#  SEED DATA
# ════════════════════════════════════════════

CATEGORY_IMAGES = {
    "Chicken":"https://images.unsplash.com/photo-1610057099443-fde8c4d50f91?q=80&w=800&auto=format&fit=crop",
    "Mutton": "https://images.unsplash.com/photo-1606728035253-49e8a23146de?q=80&w=800&auto=format&fit=crop",
    "Beef":   "https://images.unsplash.com/photo-1607116667981-d6873bb14e5a?q=80&w=800&auto=format&fit=crop",
    "Rice":   "https://images.unsplash.com/photo-1563379926898-05f4575a45d8?q=80&w=800&auto=format&fit=crop",
    "BBQ":    "https://images.unsplash.com/photo-1529193591184-b1d58069ecdd?q=80&w=800&auto=format&fit=crop",
    "Bread":  "https://images.unsplash.com/photo-1601379760883-1bb497c9d4f7?q=80&w=800&auto=format&fit=crop",
    "Drinks": "https://images.unsplash.com/photo-1437418747212-8d9709afab22?q=80&w=800&auto=format&fit=crop",
}

MENU_SEED = [
    ("Chicken","Chicken Broast",45,25),("Chicken","Chicken Karahi",80,45),
    ("Chicken","Shinwari Karahi",45,25),("Chicken","Chicken Kurma",60,35),
    ("Chicken","Desi Murgh Black Pepper Qorma",75,40),("Chicken","Boneless Handi",70,40),
    ("Chicken","Desi Murgh Makhni Karahi",80,45),("Chicken","Chicken Green Chilli",75,0),
    ("Mutton","Mutton Breast",80,25),("Mutton","Mutton Karahi",85,45),
    ("Mutton","Mutton Makhni Handi",100,55),("Mutton","Mutton Champ",70,0),
    ("Mutton","Mutton Kurma",80,46),("Mutton","Mutton Handi",89,50),
    ("Mutton","Mutton Achari Karahi",80,30),("Mutton","Mutton Black Pepper Karahi",89,50),
    ("Mutton","Mutton Lamb Shanks",85,45),
    ("Beef","Beef Nehari",16,8),("Beef","Beef Karahi",75,40),
    ("Beef","Beef Steam Boti",45,0),("Beef","Beef Kurma",75,40),
    ("Beef","Beef Handi",80,45),("Beef","Daigi Beef Biryani & Palao",80,0),
    ("Rice","Chicken Kebab Rice",22,0),("Rice","Plain Biryani Rice",10,0),
    ("Rice","Plain Rice",6,0),("Rice","Daigi Beef Pulao & Biryani (1kg)",80,0),
    ("Rice","Daigi Chicken Biryani & Palao (1kg)",70,0),
    ("Rice","Daigi Mutton Biryani & Palao (1kg)",80,0),("Rice","Vegetable Biryani",14,0),
    ("BBQ","Chicken Kabab",12,0),("BBQ","Beef Kabab",12,0),("BBQ","Angara Kabab",10,0),
    ("BBQ","Chicken Tikka",12,0),("BBQ","Shahtuk Kabab",12,0),
    ("BBQ","Chicken Tikka Boti",12,0),("BBQ","Shahtuk Beef",12,0),
    ("BBQ","Malai Boti",12,0),("BBQ","Boneless Grill Fish",18,0),
    ("BBQ","Chicken Tandoor",18,0),("BBQ","Gulfi Grill Cheese Kabab",25,0),
    ("Bread","Chapati",2.5,0),("Bread","Plain Naan",3,0),("Bread","Aloo Paratha",2.5,0),
    ("Bread","Garlic Naan",3,0),("Bread","Rogni Naan",3.5,0),
    ("Bread","Cheese Naan",10,0),("Bread","Double Cheese Naan",12,0),
    ("Drinks","Fresh Juice",7,0),("Drinks","Coca-Cola",3,0),("Drinks","Sprite",3,0),
    ("Drinks","Pepsi",3,0),("Drinks","100 Plus",3,0),("Drinks","Air Mineral",2,0),
]

ADDON_SEED = [
    ("Extra Raita",3,0),("Extra Gravy/Salan",5,0),("Extra Cheese",6,0),
    ("Extra Spicy",0,0),("Less Spicy",0,0),("Boneless",5,0),
    ("Extra Naan",3,0),("Salad",4,0),
]

DEFAULT_SETTINGS = {
    "logo_url":"","footer_text":"A True Taste of Pakistan",
    "hero_image_url":"https://images.unsplash.com/photo-1631515243349-e0cb75fb8d3a?q=80&w=2069&auto=format&fit=crop",
    "about_image_url":"https://images.unsplash.com/photo-1555939594-58d7cb561ad1?q=80&w=1200&auto=format&fit=crop",
    "about_text":"Islamabad Restaurant & Cafe brings the daig — the traditional copper cooking pot of Pakistani weddings and street kitchens — to Kuala Lumpur. Every biryani and karahi is built on premium ingredients, authentic family recipes, and patience: nothing here is rushed.",
    "tax_rate":"6",
    "currency":"RM",
    # Touch 'n Go
    "tng_qr_url":"",       # upload your TnG Business QR image here
    "tng_phone":"",        # your TnG registered phone (shown to customer)
    "tng_name":"",         # account name shown to customer
    # HitPay (also configurable from admin panel)
    "hitpay_api_key":"",
    "hitpay_salt":"",
    "hitpay_sandbox":"true",
    # Branding — editable from Admin → Site Settings, override the RESTAURANT
    # constant in code. Blank = fall back to the code default.
    "site_name":"","site_tagline":"","site_description":"","site_address":"","site_phone":"",
    # Logo shown while the site is in dark mode (usually a light/white logo)
    # and while in light mode (usually a dark logo) — set both from Admin.
    "logo_dark_mode_url":"","logo_light_mode_url":"",
    "favicon_url":"",              # browser-tab icon — blank = ships-with-template default
    "color_primary":"#C65A1E",     # brand accent color — links, highlights, "accent" everywhere
    "color_button":"",             # button fill color — blank = same as color_primary
    "color_bg_dark":"",            # dark-mode page background — blank = site default (#0a0a0a)
    "color_bg_light":"",           # light-mode page background — blank = site default (#f7f4ee)
    "theme_default":"dark",        # dark / light — what first-time visitors see
    # Email (SMTP) — used for bulk marketing email + registration verification links
    "smtp_host":"smtp.gmail.com","smtp_port":"587","smtp_user":"","smtp_pass":"",
    # Master PIN override — blank = use the ADMIN_PIN env var set on the server.
    # Settable from Admin → Security so it doesn't require server/SSH access to change.
    "master_pin":"",
}

WAITER_SEED = ["Ali","Hassan","Hamza","Rony","Jacky"]

STAFF_SEED = [
    # username, password, role
    ("admin",   "admin123",   "admin"),
    ("manager", "manager123", "manager"),
    ("staff1",  "staff123",   "staff"),
    ("staff2",  "staff123",   "staff"),
]

def seed():
    # categories
    if Category.query.count() == 0:
        for i,cat in enumerate(["Chicken","Mutton","Beef","Rice","BBQ","Bread","Drinks"]):
            db.session.add(Category(name=cat,image_url=CATEGORY_IMAGES.get(cat,""),sort_order=i))
    # menu
    if MenuItem.query.count() == 0:
        for i,(cat,name,pf,ph) in enumerate(MENU_SEED):
            db.session.add(MenuItem(category=cat,name=name,price_full=pf,price_half=ph,
                sort_order=i,available=True,image_url=CATEGORY_IMAGES.get(cat,"")))
    # addons
    if AddOn.query.count() == 0:
        for name,price,_ in ADDON_SEED:
            db.session.add(AddOn(name=name,price=price,available=True))
    # settings
    if SiteSetting.query.count() == 0:
        for k,v in DEFAULT_SETTINGS.items():
            db.session.add(SiteSetting(key=k,value=v))
    # tables
    if RestaurantTable.query.count() == 0:
        for n in range(1,13):
            db.session.add(RestaurantTable(number=n,label=f"Table {n}"))
    # waiters
    if Waiter.query.count() == 0:
        for n in WAITER_SEED:
            db.session.add(Waiter(name=n,active=True))
    # staff users
    if StaffUser.query.count() == 0:
        for uname, pwd, role in STAFF_SEED:
            u = StaffUser(username=uname, role=role, active=True)
            u.set_password(pwd)
            db.session.add(u)
    db.session.commit()

def get_settings():
    rows = {r.key:r.value for r in SiteSetting.query.all()}
    return {**DEFAULT_SETTINGS, **rows}

def get_restaurant_info():
    """RESTAURANT constant + any admin-editable overrides from Site Settings.
    Use this (not the raw RESTAURANT dict) wherever restaurant info is
    rendered, so name/tagline/address/phone/color are editable from Admin
    without touching code."""
    s = get_settings()
    return {
        **RESTAURANT,
        "name":         s.get("site_name") or RESTAURANT["name"],
        "tagline":      s.get("site_tagline") or RESTAURANT["tagline"],
        "address":      s.get("site_address") or RESTAURANT["address"],
        "phone":        s.get("site_phone") or RESTAURANT["phone"],
        "primary":      s.get("color_primary") or RESTAURANT["primary"],
        "button_color": s.get("color_button") or s.get("color_primary") or RESTAURANT["primary"],
        "bg_dark":      s.get("color_bg_dark") or "#0a0a0a",
        "bg_light":     s.get("color_bg_light") or "#f7f4ee",
        "theme_default": s.get("theme_default") or "dark",
        "logo_dark_mode_url":  s.get("logo_dark_mode_url") or s.get("logo_url") or "",
        "logo_light_mode_url": s.get("logo_light_mode_url") or s.get("logo_dark_mode_url") or s.get("logo_url") or "",
        "favicon_url":  s.get("favicon_url") or "",
    }

def get_category_order():
    return [c.name for c in Category.query.order_by(Category.sort_order).all()]

def next_order_no():
    today = datetime.datetime.now().strftime("%y%m%d")
    count = Order.query.filter(Order.order_no.like(f"MB{today}%")).count() + 1
    return f"MB{today}{count:03d}"

def next_token():
    """Daily token T001, T002... resets every day."""
    today = datetime.date.today()
    count = Order.query.filter(
        db.func.date(Order.created_at) == today
    ).count() + 1
    return f"T{count:03d}"

def serialize_order(o):
    return {
        "id":o.id,"order_no":o.order_no,"order_type":o.order_type,
        "table_number":o.table_number,"customer_name":o.customer_name,
        "customer_phone":o.customer_phone,"delivery_address":o.delivery_address or "",
        "waiter_name":o.waiter_name or "",
        "notes":o.notes or "","status":o.status,"payment_status":o.payment_status,
        "payment_method":o.payment_method,"subtotal":o.subtotal,"tax":o.tax,
        "service_charge":o.service_charge or 0,"discount_type":o.discount_type or "none",
        "discount_value":o.discount_value or 0,"discount_amount":o.discount_amount or 0,
        "total":o.total,"customer_paid":o.customer_paid or 0,"change_due":o.change_due or 0,
        "source":o.source,"platform_order_id":o.platform_order_id or "",
        "token_no":o.token_no or "","takeaway_no":o.takeaway_no,
        "created_at":o.created_at.strftime("%Y-%m-%d %H:%M"),
        "created_at_iso":o.created_at.isoformat(),
        "items":[{"name":i.name,"size":i.size,"qty":i.qty,"unit_price":i.unit_price,
                  "menu_item_id":i.menu_item_id,"addons":i.addons,
                  "addons_total":i.addons_total,"line_total":i.line_total,
                  "notes":i.notes} for i in o.items],
    }

def free_table(table_number):
    if table_number:
        t = RestaurantTable.query.filter_by(number=int(table_number)).first()
        if t: t.status = "free"

def build_order_items(cart, order):
    subtotal = 0
    for line in cart:
        # Open item — custom name + price, no menu_item_id
        if line.get("open_item"):
            unit_price = float(line.get("price") or 0)
            qty        = int(line.get("qty",1))
            oi = OrderItem(
                menu_item_id=None, name=line.get("name","Custom Item"),
                size="full", qty=qty, unit_price=unit_price,
                notes=line.get("notes",""), addons_json="[]"
            )
            subtotal += unit_price * qty
            order.items.append(oi)
            continue
        # Regular menu item
        item = db.session.get(MenuItem, line.get("id"))
        if not item: continue
        size       = line.get("size","full")
        unit_price = float(line.get("price") or (item.price_full if size=="full" else item.price_half))
        qty        = int(line.get("qty",1))
        addons     = line.get("addons",[]) or []
        addon_total= sum(a.get("price",0) for a in addons)
        oi = OrderItem(
            menu_item_id=item.id, name=item.name, size=size,
            qty=qty, unit_price=unit_price, notes=line.get("notes",""),
            addons_json=json.dumps(addons)
        )
        subtotal += (unit_price + addon_total) * qty
        order.items.append(oi)
    return round(subtotal, 2)

# ════════════════════════════════════════════
#  SECURITY HEADERS + CLOUDFLARE
# ════════════════════════════════════════════

@app.after_request
def add_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"]        = "SAMEORIGIN"
    resp.headers["Referrer-Policy"]        = "strict-origin-when-cross-origin"
    resp.headers["X-XSS-Protection"]       = "1; mode=block"
    resp.headers["Permissions-Policy"]     = "geolocation=(), microphone=(), camera=()"
    # Cache static assets aggressively (Cloudflare will also cache these)
    if request.path.startswith("/static/"):
        resp.headers["Cache-Control"] = "public, max-age=31536000, immutable"
    elif request.path.startswith("/admin/qr/"):
        resp.headers["Cache-Control"] = "public, max-age=86400"
    else:
        resp.headers["Cache-Control"] = "no-store"
    # Real IP from Cloudflare
    if "CF-Connecting-IP" in request.headers:
        resp.headers["X-Real-IP"] = request.headers["CF-Connecting-IP"]
    return resp

@app.errorhandler(404)
def not_found(e):
    return render_template("404.html", restaurant=get_restaurant_info()), 404

@app.errorhandler(500)
def server_error(e):
    return render_template("500.html", restaurant=get_restaurant_info()), 500

# ════════════════════════════════════════════
#  HITPAY INTEGRATION
# ════════════════════════════════════════════

def _hitpay_config():
    """Get HitPay API key + salt (env vars first, then DB settings)."""
    api_key = app.config.get("HITPAY_API_KEY") or ""
    salt    = app.config.get("HITPAY_SALT") or ""
    sandbox = app.config.get("HITPAY_SANDBOX", True)
    if not api_key:
        s = get_settings()
        api_key = s.get("hitpay_api_key","")
        salt    = s.get("hitpay_salt","")
        sandbox_val = s.get("hitpay_sandbox","true").lower()
        sandbox = sandbox_val in ("true","1","yes")
    base = "https://api.sandbox.hit-pay.com/v1" if sandbox else "https://api.hit-pay.com/v1"
    return api_key, salt, base


def hitpay_create_payment(order):
    """Call HitPay API using requests library."""
    import requests as req_lib
    api_key, salt, base = _hitpay_config()
    if not api_key:
        return None, None, "HitPay API key not configured."
    data = {
        "amount":             f"{order.total:.2f}",
        "currency":           "MYR",
        "name":               order.customer_name or "Customer",
        "phone":              order.customer_phone or "",
        "purpose":            f"Order {order.order_no}",
        "reference_number":   order.order_no,
        "redirect_url":       f"{SITE_URL}/payment/hitpay/return/{order.order_no}",
        "webhook":            f"{SITE_URL}/payment/hitpay/webhook",

    }
    headers = {
        "X-BUSINESS-API-KEY": api_key,
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json",
        "User-Agent": "IslamabadRestaurantCafe/1.0",
    }
    try:
        r = req_lib.post(f"{base}/payment-requests", data=data, headers=headers, timeout=15)
        if r.status_code in (200, 201):
            d = r.json()
            return d.get("url"), d.get("id"), None
        return None, None, f"HTTP {r.status_code}: {r.text[:100]}"
    except Exception as e:
        return None, None, str(e)
def restaurant_name():
    return RESTAURANT["name"]


def hitpay_verify_webhook(raw_body: bytes, signature: str, salt: str = "") -> bool:
    """Verify HitPay webhook HMAC-SHA256 signature."""
    import hmac as _hmac, hashlib
    _, _salt, _ = _hitpay_config()
    use_salt = salt or _salt
    computed = _hmac.new(use_salt.encode(), raw_body, hashlib.sha256).hexdigest()
    return _hmac.compare_digest(computed, signature)


@app.route("/api/hitpay/create", methods=["POST"])
def api_hitpay_create():
    """Create HitPay payment request from customer cart."""
    data  = request.get_json(silent=True) or {}
    cart  = data.get("cart", [])
    if not cart:
        return jsonify({"error": "Cart is empty"}), 400

    # Create the order in "pending" state first
    table_number = data.get("table_number") or None
    order = Order(
        order_no       = next_order_no(),
        order_type     = data.get("order_type", "dine_in"),
        table_number   = int(table_number) if table_number else None,
        customer_name  = data.get("customer_name", ""),
        customer_phone = data.get("customer_phone", ""),
        delivery_address = data.get("delivery_address","") if data.get("order_type")=="delivery" else "",
        customer_id    = session.get("customer_id"),
        status         = "pending",
        payment_method = "hitpay",
        payment_status = "unpaid",
        source         = "qr" if table_number else "online",
    )
    settings = get_settings()
    tax_rate = float(settings.get("tax_rate", "6")) / 100
    subtotal = build_order_items(cart, order)
    order.subtotal = subtotal
    order.tax      = round(subtotal * tax_rate, 2)
    order.total    = round(subtotal + order.tax, 2)
    db.session.add(order)
    db.session.commit()

    # Call HitPay API
    checkout_url, payment_request_id, error = hitpay_create_payment(order)
    if error:
        # Don't fail the order — save it and return error so customer can try another method
        return jsonify({"error": error, "order_no": order.order_no}), 502

    # Save HitPay payment request ID in notes
    order.notes = f"HitPay:{payment_request_id}"
    db.session.commit()

    return jsonify({
        "order_no":           order.order_no,
        "order_id":           order.id,
        "total":              order.total,
        "checkout_url":       checkout_url,
        "payment_request_id": payment_request_id,
    })


@app.route("/payment/hitpay/return/<order_no>")
def hitpay_return(order_no):
    """Customer lands here after HitPay checkout. status=paid/failed comes as query param."""
    order  = Order.query.filter_by(order_no=order_no).first_or_404()
    status = request.args.get("status", "")
    # Redirect to live order tracking — webhook will do the actual payment confirmation
    return redirect(url_for("customer_track", order_no=order_no))


@app.route("/payment/hitpay/webhook", methods=["POST"])
def hitpay_webhook():
    """HitPay webhook — marks order as paid after HMAC verification."""
    raw_body  = request.get_data()
    signature = request.headers.get("Hitpay-Signature", "")
    _, salt, _ = _hitpay_config()
    if not salt:
        app.logger.error("HitPay webhook rejected: HITPAY_SALT not configured")
        return "Webhook not configured", 500
    if not signature or not hitpay_verify_webhook(raw_body, signature, salt):
        app.logger.warning("HitPay webhook: invalid signature")
        return "Invalid signature", 401
    try:
        payload = json.loads(raw_body)
    except Exception:
        return "Bad JSON", 400

    if payload.get("status") != "completed":
        return "OK", 200   # ignore non-completed events

    ref = payload.get("reference_number", "")
    order = Order.query.filter_by(order_no=ref).first()
    if not order:
        app.logger.warning(f"HitPay webhook: order {ref} not found")
        return "Order not found", 404

    if order.payment_status != "paid":
        payments = payload.get("payments", [])
        method   = payments[0].get("payment_type", "hitpay") if payments else "hitpay"
        order.payment_status = "paid"
        order.payment_method = method
        order.status         = "confirmed"
        order.customer_paid  = order.total
        order.change_due     = 0
        db.session.commit()
        app.logger.info(f"HitPay: order {ref} marked PAID via {method}")

    return "OK", 200

# ════════════════════════════════════════════
#  SECURITY HELPERS
# ════════════════════════════════════════════

def get_real_ip():
    """Get real IP — works behind Cloudflare Tunnel/Nginx.
    Only trusts forwarded-IP headers when the TCP connection itself came
    from the local trusted proxy (127.0.0.1). Otherwise a client could
    connect directly to Flask and forge these headers to spoof any IP
    (e.g. to fake "127.0.0.1" and bypass the internal-only / whitelist
    checks below)."""
    if request.remote_addr in ("127.0.0.1", "::1"):
        for header in ["CF-Connecting-IP", "X-Real-IP", "X-Forwarded-For"]:
            ip = request.headers.get(header)
            if ip:
                return ip.split(",")[0].strip()
    return request.remote_addr or "unknown"

def is_ip_allowed(path="/admin"):
    """Check if current IP is in whitelist. If whitelist empty → allow all."""
    whitelist = IPWhitelist.query.all()
    if not whitelist:
        return True  # no restriction
    ip = get_real_ip()
    return any(w.ip_address == ip for w in whitelist)

def is_rate_limited(ip):
    """Block IP after 5 failed attempts for 15 minutes."""
    fa = FailedAttempt.query.filter_by(ip_address=ip).first()
    if not fa:
        return False
    if fa.locked_until and datetime.datetime.utcnow() < fa.locked_until:
        return True
    if fa.locked_until and datetime.datetime.utcnow() >= fa.locked_until:
        db.session.delete(fa)
        db.session.commit()
    return False

def record_failed(ip):
    fa = FailedAttempt.query.filter_by(ip_address=ip).first()
    if not fa:
        fa = FailedAttempt(ip_address=ip, count=1)
        db.session.add(fa)
    else:
        fa.count += 1
        fa.updated_at = datetime.datetime.utcnow()
        if fa.count >= 5:
            fa.locked_until = datetime.datetime.utcnow() + datetime.timedelta(minutes=15)
    db.session.commit()

def record_success(ip):
    fa = FailedAttempt.query.filter_by(ip_address=ip).first()
    if fa:
        db.session.delete(fa)
        db.session.commit()

def log_login(username, success, path="/admin"):
    db.session.add(LoginLog(
        username=username, ip_address=get_real_ip(),
        success=success, path=path
    ))
    db.session.commit()

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("staff_id"):
            return redirect(url_for("staff_login", next=request.path))
        user = db.session.get(StaffUser, session["staff_id"])
        if not user or not user.active:
            session.clear()
            return redirect(url_for("staff_login"))
        if user.role not in ("admin", "manager"):
            return render_template("403.html", restaurant=get_restaurant_info()), 403
        if not is_ip_allowed("/admin"):
            return render_template("403.html", restaurant=get_restaurant_info(), reason="IP not whitelisted"), 403
        return f(*args, **kwargs)
    return decorated

def staff_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("staff_id"):
            return redirect(url_for("staff_login", next=request.path))
        user = db.session.get(StaffUser, session["staff_id"])
        if not user or not user.active:
            session.clear()
            return redirect(url_for("staff_login"))
        if not is_ip_allowed("/pos"):
            return render_template("403.html", restaurant=get_restaurant_info(), reason="IP not whitelisted"), 403
        # Kitchen staff can only access kitchen
        if user.role == "kitchen" and request.path not in ["/kitchen", "/logout"]:
            return redirect("/kitchen")
        return f(*args, **kwargs)
    return decorated

# ════════════════════════════════════════════
#  AUTH ROUTES
# ════════════════════════════════════════════

@app.route("/login", methods=["GET","POST"])
def staff_login():
    ip = get_real_ip()
    error = ""
    next_url = request.args.get("next", "/pos")

    if is_rate_limited(ip):
        error = "Too many failed attempts. Try again in 15 minutes."
        return render_template("staff_login.html", restaurant=get_restaurant_info(),
                               error=error, next_url=next_url)

    if request.method == "POST":
        username = request.form.get("username","").strip().lower()
        password = request.form.get("password","")
        user = StaffUser.query.filter_by(username=username, active=True).first()
        if user and user.check_password(password):
            record_success(ip)
            log_login(username, True, next_url)
            session.permanent = True
            session["staff_id"]   = user.id
            session["staff_name"] = user.username
            session["staff_role"] = user.role
            user.last_login = datetime.datetime.utcnow()
            db.session.commit()
            # Role-based redirect
            if user.role == "kitchen":
                return redirect("/kitchen")
            elif user.role in ("admin", "manager"):
                return redirect(next_url if next_url.startswith("/") else "/admin")
            else:
                return redirect(next_url if next_url.startswith("/") else "/pos")
        else:
            record_failed(ip)
            log_login(username, False, next_url)
            error = "Wrong username or password."

    return render_template("staff_login.html", restaurant=get_restaurant_info(),
                           error=error, next_url=next_url)

@app.route("/logout")
def staff_logout():
    session.clear()
    return redirect(url_for("staff_login"))

# Keep old admin/login for backwards compat → redirect to new login
@app.route("/admin/login", methods=["GET","POST"])
def admin_login():
    return redirect(url_for("staff_login", next="/admin"))

@app.route("/admin/logout")
def admin_logout():
    session.clear()
    return redirect(url_for("staff_login"))

# ════════════════════════════════════════════
#  PUBLIC PAGES
# ════════════════════════════════════════════




@app.route("/api/popup-reset")
def api_popup_reset():
    session.pop("popup_shown", None)
    return jsonify({"ok":True})

@app.route("/api/popup-shown", methods=["POST"])
def api_popup_shown():
    session["popup_shown"] = True
    return jsonify({"ok":True})

@app.route("/reserve", methods=["GET","POST"])
def reservation_page():
    if request.method == "POST":
        data  = request.form
        name  = data.get("name","").strip()
        phone = data.get("phone","").strip()
        email = data.get("email","").strip()
        date  = data.get("date","")
        time  = data.get("time","")
        guests= int(data.get("guests",2))
        notes = data.get("notes","").strip()
        if not name or not phone or not date or not time:
            return render_template("reservation.html", restaurant=get_restaurant_info(),
                error="Please fill all required fields", settings=get_settings(), now=datetime.datetime.now())
        try:
            import datetime as dt
            res_date = dt.date.fromisoformat(date)
        except:
            return render_template("reservation.html", restaurant=get_restaurant_info(),
                error="Invalid date", settings=get_settings(), now=datetime.datetime.now())
        r = Reservation(name=name, phone=phone, email=email,
                        date=res_date, time=time, guests=guests, notes=notes)
        db.session.add(r)
        db.session.commit()
        return render_template("reservation.html", restaurant=get_restaurant_info(),
            success=True, ref=f"RES{r.id:04d}", settings=get_settings(), now=datetime.datetime.now())
    return render_template("reservation.html", restaurant=get_restaurant_info(),
        error="", settings=get_settings(), now=datetime.datetime.now())


@app.route("/api/admin/customers")
@admin_required
def api_admin_customers():
    q = request.args.get("q","").strip()
    custs = Customer.query.order_by(Customer.created_at.desc()).all()
    result = []
    for cust in custs:
        if q and q.lower() not in cust.name.lower() and q.lower() not in cust.email.lower():
            continue
        orders = Order.query.filter_by(customer_id=cust.id).order_by(Order.created_at.desc()).all()
        total_spent = sum(o.total for o in orders if o.payment_status=='paid')
        result.append({
            "id": cust.id, "name": cust.name, "email": cust.email,
            "phone": cust.phone or "", "order_count": len(orders),
            "total_spent": total_spent,
            "created_at": cust.created_at.strftime("%d %b %Y") if cust.created_at else "",
            "orders": [{"order_no":o.order_no,"total":o.total,"status":o.status,
                        "created_at":o.created_at.strftime("%d %b %Y") if o.created_at else ""} for o in orders[:5]]
        })
    return jsonify(result)

def smtp_configured():
    s = get_settings()
    return bool(s.get("smtp_user") and s.get("smtp_pass"))

def send_email(to_email, subject, html_body):
    """Send one HTML email via the SMTP settings configured in Admin →
    Site Settings → Email (SMTP). Returns True on success, False if SMTP
    isn't configured or sending failed (caller decides whether that's fatal)."""
    import smtplib
    from email.mime.text import MIMEText
    from email.mime.multipart import MIMEMultipart
    s = get_settings()
    smtp_host = s.get("smtp_host","smtp.gmail.com")
    smtp_port = int(s.get("smtp_port","587") or 587)
    smtp_user = s.get("smtp_user","")
    smtp_pass = s.get("smtp_pass","")
    if not smtp_user or not smtp_pass:
        return False
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"]    = f"{get_restaurant_info()['name']} <{smtp_user}>"
        msg["To"]      = to_email
        msg.attach(MIMEText(html_body, "html"))
        with smtplib.SMTP(smtp_host, smtp_port, timeout=15) as srv:
            srv.starttls()
            srv.login(smtp_user, smtp_pass)
            srv.sendmail(smtp_user, to_email, msg.as_string())
        return True
    except Exception as e:
        app.logger.warning(f"send_email failed to {to_email}: {e}")
        return False

def send_verification_email(customer):
    r = get_restaurant_info()
    link = f"{SITE_URL}/verify-email/{customer.verify_token}"
    html_body = f"""<html><body style="font-family:Arial,sans-serif;background:#0a0a0a;color:#fff;padding:20px;">
    <div style="max-width:600px;margin:0 auto;background:#111;border-radius:16px;padding:30px;">
    <h1 style="color:{r['primary']};font-family:serif;">{r['name']}</h1>
    <p>Hi {customer.name},</p>
    <p>Thanks for creating an account. Please confirm your email address to activate it:</p>
    <p style="text-align:center;margin:28px 0;">
      <a href="{link}" style="background:{r['primary']};color:#fff;padding:12px 28px;border-radius:8px;text-decoration:none;font-weight:bold;display:inline-block;">Verify My Email</a>
    </p>
    <p style="color:#888;font-size:12px;">Or paste this link in your browser:<br>{link}</p>
    <hr style="border-color:#333;margin:20px 0">
    <p style="color:#666;font-size:12px;">{r['name']} · {r['address']}</p>
    </div></body></html>"""
    return send_email(customer.email, f"Verify your email — {r['name']}", html_body)

@app.route("/api/admin/bulk-email", methods=["POST"])
@admin_required
def api_admin_bulk_email():
    data = request.get_json(silent=True) or {}
    subject = data.get("subject","")
    body    = data.get("body","")
    if not smtp_configured():
        return jsonify({"message":"SMTP not configured. Add it in Site Settings → Email."})
    r = get_restaurant_info()
    html_body = f"""<html><body style="font-family:Arial,sans-serif;background:#0a0a0a;color:#fff;padding:20px;">
    <div style="max-width:600px;margin:0 auto;background:#111;border-radius:16px;padding:30px;">
    <h1 style="color:{r['primary']};font-family:serif;">{r['name']}</h1>
    <p>{body.replace(chr(10),'<br>')}</p>
    <hr style="border-color:#333;margin:20px 0">
    <p style="color:#666;font-size:12px;">{r['name']} · {r['address']}</p>
    </div></body></html>"""
    custs = Customer.query.filter_by(active=True).all()
    sent = sum(1 for c in custs if c.email and send_email(c.email, subject, html_body))
    return jsonify({"message":f"Sent to {sent} customers!"})

@app.route("/api/admin/reservations")
@admin_required
def api_admin_reservations():
    date = request.args.get("date","")
    q = Reservation.query.order_by(Reservation.date, Reservation.time)
    if date:
        try:
            import datetime as dt
            q = q.filter(Reservation.date == dt.date.fromisoformat(date))
        except: pass
    return jsonify([{"id":r.id,"name":r.name,"phone":r.phone,"email":r.email,
                     "date":r.date.isoformat(),"time":r.time,"guests":r.guests,
                     "notes":r.notes,"status":r.status} for r in q.all()])

@app.route("/api/admin/reservation/<int:rid>/status", methods=["POST"])
@admin_required
def api_admin_reservation_status(rid):
    r = db.get_or_404(Reservation, rid)
    r.status = (request.get_json(silent=True) or {}).get("status","pending")
    db.session.commit()
    return jsonify({"ok":True})



# ════════════════════════════════════════════
#  GOOGLE OAUTH
# ════════════════════════════════════════════
GOOGLE_CLIENT_ID     = os.environ.get("GOOGLE_CLIENT_ID", "")
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET", "")
GOOGLE_REDIRECT_URI  = os.environ.get("GOOGLE_REDIRECT_URI", f"{SITE_URL}/auth/google/callback")
GOOGLE_AUTH_URL      = "https://accounts.google.com/o/oauth2/auth"
GOOGLE_TOKEN_URL     = "https://oauth2.googleapis.com/token"
GOOGLE_USERINFO_URL  = "https://www.googleapis.com/oauth2/v2/userinfo"

@app.route("/auth/google")
def google_login():
    import urllib.parse, secrets as _secrets
    if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET:
        return redirect(url_for("customer_login"))
    state = _secrets.token_hex(16)
    session["oauth_state"] = state
    params = {
        "client_id":     GOOGLE_CLIENT_ID,
        "redirect_uri":  GOOGLE_REDIRECT_URI,
        "response_type": "code",
        "scope":         "openid email profile",
        "state":         state,
        "access_type":   "offline",
    }
    return redirect(GOOGLE_AUTH_URL + "?" + urllib.parse.urlencode(params))

@app.route("/auth/google/callback")
def google_callback():
    import requests as _req
    if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET:
        return redirect(url_for("customer_login"))
    code  = request.args.get("code","")
    state = request.args.get("state","")
    if not code or not session.get("oauth_state") or not hmac.compare_digest(state, session.get("oauth_state","")):
        return redirect(url_for("customer_login"))
    session.pop("oauth_state", None)
    # Exchange code for token
    token_resp = _req.post(GOOGLE_TOKEN_URL, data={
        "code":          code,
        "client_id":     GOOGLE_CLIENT_ID,
        "client_secret": GOOGLE_CLIENT_SECRET,
        "redirect_uri":  GOOGLE_REDIRECT_URI,
        "grant_type":    "authorization_code",
    })
    if not token_resp.ok:
        return redirect(url_for("customer_login"))
    tokens = token_resp.json()
    # Get user info
    user_resp = _req.get(GOOGLE_USERINFO_URL,
        headers={"Authorization": f"Bearer {tokens['access_token']}"})
    if not user_resp.ok:
        return redirect(url_for("customer_login"))
    info = user_resp.json()
    email = info.get("email","").lower()
    name  = info.get("name","")
    if not email:
        return redirect(url_for("customer_login"))
    # Find or create customer
    cust = Customer.query.filter_by(email=email).first()
    if not cust:
        import hashlib as _hl, secrets as _sec
        cust = Customer(
            name=name, email=email, phone="",
            password_hash=_hl.sha256(_sec.token_hex(32).encode()).hexdigest(),
            active=True
        )
        db.session.add(cust)
        db.session.commit()
    elif not cust.active:
        return redirect(url_for("customer_login"))
    session["customer_id"]   = cust.id
    session["customer_name"] = cust.name
    return redirect(url_for("customer_dashboard"))


# ════════════════════════════════════════════
#  CUSTOMER AUTH
# ════════════════════════════════════════════

@app.route("/register", methods=["GET","POST"])
def customer_register():
    if request.method == "POST":
        name     = request.form.get("name","").strip()
        email    = request.form.get("email","").strip().lower()
        phone    = request.form.get("phone","").strip()
        address  = request.form.get("address","").strip()
        password = request.form.get("password","")
        if not name or not email or not password:
            return render_template("customer_register.html", restaurant=get_restaurant_info(),
                                   error="All fields required", settings=get_settings())
        if Customer.query.filter_by(email=email).first():
            return render_template("customer_register.html", restaurant=get_restaurant_info(),
                                   error="Email already registered. Please login.", settings=get_settings())
        cust = Customer(name=name, email=email, phone=phone, address=address)
        cust.set_password(password)
        cust.verify_token = secrets.token_urlsafe(32)
        cust.verify_token_sent = datetime.datetime.utcnow()
        db.session.add(cust)
        db.session.commit()
        if smtp_configured():
            send_verification_email(cust)
        session["customer_id"]   = cust.id
        session["customer_name"] = cust.name
        return redirect(url_for("customer_dashboard"))
    return render_template("customer_register.html", restaurant=get_restaurant_info(),
                           error="", settings=get_settings())

@app.route("/verify-email/<token>")
def verify_email(token):
    cust = Customer.query.filter_by(verify_token=token).first()
    if not cust:
        return render_template("customer_login.html", restaurant=get_restaurant_info(),
                               error="Invalid or expired verification link.", settings=get_settings())
    cust.email_verified = True
    cust.verify_token = ""
    db.session.commit()
    if session.get("customer_id") == cust.id:
        return redirect(url_for("customer_dashboard", verified=1))
    session["customer_id"]   = cust.id
    session["customer_name"] = cust.name
    return redirect(url_for("customer_dashboard", verified=1))

@app.route("/api/customer/resend-verification", methods=["POST"])
def api_resend_verification():
    cid = session.get("customer_id")
    if not cid:
        return jsonify({"error":"Not logged in"}), 401
    cust = db.session.get(Customer, cid)
    if not cust:
        return jsonify({"error":"Not found"}), 404
    if cust.email_verified:
        return jsonify({"error":"Already verified"}), 400
    # Simple resend cooldown — 60s
    if cust.verify_token_sent and (datetime.datetime.utcnow() - cust.verify_token_sent).total_seconds() < 60:
        return jsonify({"error":"Please wait a minute before requesting another email."}), 429
    if not cust.verify_token:
        cust.verify_token = secrets.token_urlsafe(32)
    cust.verify_token_sent = datetime.datetime.utcnow()
    db.session.commit()
    if not smtp_configured():
        return jsonify({"error":"Email sending isn't configured yet. Ask the restaurant to set it up."}), 503
    ok = send_verification_email(cust)
    if not ok:
        return jsonify({"error":"Couldn't send email — try again shortly."}), 502
    return jsonify({"ok":True})

@app.route("/customer/login", methods=["GET","POST"])
def customer_login():
    if request.method == "POST":
        email    = request.form.get("email","").strip().lower()
        password = request.form.get("password","")
        cust = Customer.query.filter_by(email=email, active=True).first()
        if cust and cust.check_password(password):
            session["customer_id"]   = cust.id
            session["customer_name"] = cust.name
            return redirect(request.args.get("next") or url_for("customer_dashboard"))
        return render_template("customer_login.html", restaurant=get_restaurant_info(),
                               error="Wrong email or password", settings=get_settings())
    return render_template("customer_login.html", restaurant=get_restaurant_info(),
                           error="", settings=get_settings())

@app.route("/customer/logout")
def customer_logout():
    session.pop("customer_id", None)
    session.pop("customer_name", None)
    return redirect(url_for("landing"))

@app.route("/customer/dashboard")
def customer_dashboard():
    cid = session.get("customer_id")
    if not cid:
        return redirect(url_for("customer_login"))
    cust   = db.get_or_404(Customer, cid)
    orders = Order.query.filter_by(customer_id=cid).order_by(Order.created_at.desc()).limit(20).all()
    return render_template("customer_dashboard.html", customer=cust,
                           orders=orders, restaurant=get_restaurant_info(), settings=get_settings(),
                           just_verified=request.args.get("verified")=="1")

@app.route("/api/customer/profile", methods=["POST"])
def api_customer_update_profile():
    cid = session.get("customer_id")
    if not cid:
        return jsonify({"error":"Not logged in"}), 401
    cust = db.session.get(Customer, cid)
    if not cust:
        return jsonify({"error":"Not found"}), 404
    data = request.get_json(silent=True) or {}
    if "name" in data:
        name = (data.get("name") or "").strip()
        if not name:
            return jsonify({"error":"Name can't be empty"}), 400
        cust.name = name
    if "phone" in data:
        cust.phone = (data.get("phone") or "").strip()
    if "address" in data:
        cust.address = (data.get("address") or "").strip()
    db.session.commit()
    session["customer_name"] = cust.name
    return jsonify({"ok":True, "name":cust.name, "phone":cust.phone, "address":cust.address})

@app.route("/customer/track/<order_no>")
def customer_track(order_no):
    order = Order.query.filter_by(order_no=order_no).first_or_404()
    return render_template("customer_track.html", order=order,
                           restaurant=get_restaurant_info(), settings=get_settings())

@app.route("/api/order-status/<order_no>")
def api_order_status(order_no):
    order = Order.query.filter_by(order_no=order_no).first_or_404()
    return jsonify({"status": order.status, "order_no": order.order_no})

@app.route("/")
def landing():
    featured = MenuItem.query.filter_by(available=True).order_by(MenuItem.sort_order).limit(6).all()
    return render_template("landing.html", restaurant=get_restaurant_info(),
                           featured=featured, settings=get_settings())

@app.route("/order")
def customer_menu():
    # Require customer login
    if not session.get("customer_id"):
        return redirect(url_for("customer_login", next="/order"))
    # Support both token-based (secure) and number-based (legacy)
    token = request.args.get("t","")
    table = request.args.get("table","")
    
    if token:
        # Secure token-based table lookup
        valid_table = RestaurantTable.query.filter_by(token=token).first()
        table = str(valid_table.number) if valid_table else ""
    elif table:
        # Legacy - validate table exists
        valid_table = RestaurantTable.query.filter_by(number=int(table) if table.isdigit() else 0).first()
        if not valid_table:
            table = ""
    items   = MenuItem.query.filter_by(available=True).order_by(MenuItem.sort_order).all()
    addons  = AddOn.query.filter_by(available=True).all()
    grouped = {}
    for c in get_category_order():
        grouped[c] = [i for i in items if i.category == c]
    customer = db.session.get(Customer, session["customer_id"])
    return render_template("menu.html", grouped=grouped, restaurant=get_restaurant_info(),
                           table=table, addons=addons, settings=get_settings(), customer=customer)

# ════════════════════════════════════════════
#  CUSTOMER ORDER API
# ════════════════════════════════════════════

@app.route("/api/checkout", methods=["POST"])
def api_checkout():
    data   = request.get_json(silent=True) or {}
    cart   = data.get("cart",[])
    if not cart:
        return jsonify({"error":"Cart is empty"}), 400
    table_number    = data.get("table_number") or None
    payment_method  = data.get("payment_method","cash")
    tng_txn_id      = data.get("tng_txn_id","")
    order = Order(
        order_no=next_order_no(),
        order_type=data.get("order_type","dine_in"),
        table_number=int(table_number) if table_number else None,
        customer_name=data.get("customer_name",""),
        customer_phone=data.get("customer_phone",""),
        delivery_address=data.get("delivery_address","") if data.get("order_type")=="delivery" else "",
        customer_id=session.get("customer_id"),
        status="pending",
        payment_method=payment_method,
        source="qr" if table_number else "online",
        # TnG txn id saved in notes for staff to verify
        notes=f"TnG Ref: {tng_txn_id}" if tng_txn_id else "",
    )
    subtotal = build_order_items(cart, order)
    settings = get_settings()
    tax_rate = float(settings.get("tax_rate","6")) / 100
    order.subtotal = subtotal
    order.tax      = round(subtotal * tax_rate, 2)
    order.total    = round(subtotal + order.tax, 2)
    # TnG = pending_verification (staff confirm from TnG app), card/fpx = auto paid
    if payment_method == "tng":
        order.payment_status = "pending_verification"
    elif payment_method in ("card","fpx"):
        order.payment_status = "paid"
    else:
        order.payment_status = "unpaid"
    if table_number:
        t = RestaurantTable.query.filter_by(number=int(table_number)).first()
        if t: t.status = "occupied"
    db.session.add(order)
    db.session.commit()
    return jsonify({"order_no":order.order_no,"total":order.total,"order_id":order.id})

@app.route("/order-status/<order_no>")
def order_status_page(order_no):
    order = Order.query.filter_by(order_no=order_no).first_or_404()
    return render_template("order_status.html", order=order, restaurant=get_restaurant_info())

#  POS PANEL
# ════════════════════════════════════════════

@app.route("/pos")
@staff_required
def pos_panel():
    items   = MenuItem.query.filter_by(available=True).order_by(MenuItem.sort_order).all()
    addons  = AddOn.query.filter_by(available=True).all()
    grouped = {}
    for c in get_category_order():
        grouped[c] = [i for i in items if i.category == c]
    tables  = RestaurantTable.query.order_by(RestaurantTable.number).all()
    waiters = Waiter.query.filter_by(active=True).order_by(Waiter.name).all()
    return render_template("pos.html", grouped=grouped, tables=tables,
                           waiters=waiters, addons=addons, restaurant=get_restaurant_info(),
                           staff_name=session.get("staff_name",""),
                           staff_role=session.get("staff_role","staff"))

def api_staff_check(allow_kitchen=False):
    """Returns True if request is from an authenticated staff session.
    Kitchen accounts are excluded by default — the UI restricts them to
    /kitchen only, so the API must enforce the same restriction, otherwise
    a kitchen login could call POS/payment endpoints directly."""
    if not session.get("staff_id"):
        return False
    if not allow_kitchen and session.get("staff_role") == "kitchen":
        return False
    return True

@app.route("/api/pos/orders")
def api_pos_orders():
    if not api_staff_check():
        return jsonify({"error":"Unauthorized"}), 401
    status = request.args.get("status")
    q = Order.query.order_by(Order.created_at.desc())
    if status:
        q = q.filter(Order.status == status)
    return jsonify([serialize_order(o) for o in q.limit(200).all()])

@app.route("/api/pos/order", methods=["POST"])
def api_pos_create_order():
    if not api_staff_check(): return jsonify({"error":"Unauthorized"}), 401
    data = request.get_json(silent=True) or {}
    cart = data.get("cart",[])
    if not cart:
        return jsonify({"error":"Cart is empty"}), 400

    order_type   = data.get("order_type","dine_in")
    source       = data.get("source","pos")  # pos/grab/foodpanda/lalamove/shopee
    takeaway_no  = data.get("takeaway_no") or None

    order = Order(
        order_no=next_order_no(),
        token_no=next_token(),
        order_type=order_type,
        table_number=data.get("table_number") or None,
        takeaway_no=int(takeaway_no) if takeaway_no else None,
        customer_name=data.get("customer_name","Walk-In"),
        customer_phone=data.get("customer_phone",""),
        waiter_name=data.get("waiter_name",""),
        platform_order_id=data.get("platform_order_id",""),
        notes=data.get("notes",""),
        status="confirmed",
        payment_method=data.get("payment_method","cash"),
        payment_status="unpaid",
        source=source,
    )
    settings = get_settings()
    tax_rate = float(settings.get("tax_rate","6")) / 100
    subtotal = build_order_items(cart, order)
    order.subtotal = subtotal
    order.tax      = round(subtotal * tax_rate, 2)
    order.total    = round(subtotal + order.tax, 2)
    if order.table_number:
        t = RestaurantTable.query.filter_by(number=int(order.table_number)).first()
        if t: t.status = "occupied"
    db.session.add(order)
    db.session.commit()
    return jsonify(serialize_order(order))


@app.route("/api/pos/verify-master-key", methods=["POST"])
def api_verify_master_key():
    """Verify supervisor PIN before allowing item void or bill modification."""
    if not api_staff_check(): return jsonify({"error":"Unauthorized"}), 401
    data = request.get_json(silent=True) or {}
    pin  = data.get("pin","")
    # Master key = admin PIN (DB setting takes priority over the ADMIN_PIN
    # env var, so it can be changed from Admin → Security without SSH
    # access) or any admin/manager account password
    active_pin = get_settings().get("master_pin") or app.config["ADMIN_PIN"]
    if pin and hmac.compare_digest(pin, active_pin):
        return jsonify({"ok":True})
    # Also check if any admin/manager has this password
    user = StaffUser.query.filter_by(active=True).all()
    for u in user:
        if u.role in ("admin","manager") and u.check_password(pin):
            return jsonify({"ok":True})
    return jsonify({"ok":False,"error":"Wrong master key"}), 401


@app.route("/api/admin/change-pin", methods=["POST"])
@admin_required
def api_admin_change_pin():
    """Change the master PIN used for voiding/modifying bills in POS.
    Requires the CURRENT pin (or an admin/manager password) plus the new one,
    so a compromised admin session alone can't silently take over the PIN."""
    data     = request.get_json(silent=True) or {}
    current  = data.get("current_pin","")
    new_pin  = data.get("new_pin","")
    if not new_pin.isdigit() or not (4 <= len(new_pin) <= 8):
        return jsonify({"error":"New PIN must be 4-8 digits"}), 400
    active_pin = get_settings().get("master_pin") or app.config["ADMIN_PIN"]
    user = db.session.get(StaffUser, session["staff_id"])
    valid_current = hmac.compare_digest(current, active_pin) if current else False
    if not valid_current and user and not user.check_password(current):
        return jsonify({"error":"Current PIN (or your password) is incorrect"}), 401
    row = SiteSetting.query.get("master_pin")
    if not row:
        row = SiteSetting(key="master_pin", value=""); db.session.add(row)
    row.value = new_pin
    db.session.commit()
    return jsonify({"ok":True})


@app.route("/api/pos/split-bill/<int:oid>", methods=["POST"])
def api_split_bill(oid):
    """Split an order into multiple sub-orders (one per person)."""
    if not api_staff_check(): return jsonify({"error":"Unauthorized"}), 401
    original = db.get_or_404(Order, oid)
    data     = request.get_json(silent=True) or {}
    splits   = data.get("splits",[])  # [{items:[{item_idx,qty}], customer_name}]
    if not splits:
        return jsonify({"error":"No split data"}), 400

    settings = get_settings()
    tax_rate = float(settings.get("tax_rate","6")) / 100
    new_orders = []

    for sp in splits:
        if not sp.get("items"): continue
        sub = Order(
            order_no=next_order_no(),
            token_no=next_token(),
            order_type=original.order_type,
            table_number=original.table_number,
            customer_name=sp.get("customer_name","Split"),
            waiter_name=original.waiter_name,
            status="confirmed",
            payment_method=original.payment_method,
            payment_status="unpaid",
            source="pos",
            notes=f"Split from {original.order_no}",
        )
        subtotal = 0
        orig_items = original.items
        for sel in sp["items"]:
            idx = sel.get("item_idx",0)
            qty = int(sel.get("qty",1))
            if idx >= len(orig_items): continue
            oi_src = orig_items[idx]
            oi = OrderItem(
                menu_item_id=oi_src.menu_item_id,
                name=oi_src.name, size=oi_src.size,
                qty=qty, unit_price=oi_src.unit_price,
                notes=oi_src.notes, addons_json=oi_src.addons_json
            )
            addon_total = sum(a.get("price",0) for a in oi.addons)
            subtotal += (oi_src.unit_price + addon_total) * qty
            sub.items.append(oi)
        sub.subtotal = round(subtotal,2)
        sub.tax      = round(subtotal * tax_rate,2)
        sub.total    = round(subtotal + sub.tax,2)
        db.session.add(sub)
        new_orders.append(sub)

    # Mark original as split
    original.status = "cancelled"
    original.notes  = f"Split into {len(new_orders)} orders"
    db.session.commit()
    return jsonify({"ok":True,"new_orders":[serialize_order(o) for o in new_orders]})

@app.route("/api/order/<int:oid>/status", methods=["POST"])
def api_update_status(oid):
    # Kitchen display advances orders through confirmed → preparing → ready
    if not api_staff_check(allow_kitchen=True): return __import__("flask").jsonify({"error":"Unauthorized"}), 401
    order  = db.get_or_404(Order, oid)
    status = (request.get_json(silent=True) or {}).get("status")
    order.status = status
    if status in ("completed","cancelled"):
        free_table(order.table_number)
    db.session.commit()
    return jsonify(serialize_order(order))

@app.route("/api/order/<int:oid>/complete-payment", methods=["POST"])
def api_complete_payment(oid):
    if not api_staff_check(): return __import__("flask").jsonify({"error":"Unauthorized"}), 401
    order = db.get_or_404(Order, oid)
    data  = request.get_json(silent=True) or {}
    settings  = get_settings()
    tax_rate  = float(settings.get("tax_rate","6")) / 100
    svc_pct   = float(data.get("service_charge_pct") or 0)
    disc_type = data.get("discount_type","none")
    disc_val  = float(data.get("discount_value") or 0)
    c_paid    = float(data.get("customer_paid") or 0)
    subtotal  = order.subtotal
    tax       = round(subtotal * tax_rate, 2)
    svc       = round(subtotal * (svc_pct/100), 2)
    if disc_type == "percent":
        disc_amt = round(subtotal * (disc_val/100), 2)
    elif disc_type == "fixed":
        disc_amt = round(min(disc_val, subtotal), 2)
    else:
        disc_amt = 0
    grand  = round(subtotal + tax + svc - disc_amt, 2)
    change = round(max(c_paid - grand, 0), 2)
    order.tax            = tax
    order.service_charge = svc
    order.discount_type  = disc_type
    order.discount_value = disc_val
    order.discount_amount= disc_amt
    order.total          = grand
    order.customer_paid  = c_paid
    order.change_due     = change
    order.payment_method = data.get("payment_method","cash")
    order.payment_status = "paid"
    order.status         = "completed"
    free_table(order.table_number)
    db.session.commit()
    return jsonify(serialize_order(order))

@app.route("/api/order/<int:oid>/pay", methods=["POST"])
def api_mark_paid(oid):
    if not api_staff_check(): return jsonify({"error":"Unauthorized"}), 401
    order = db.get_or_404(Order, oid)
    order.payment_status = "paid"
    order.payment_method = (request.get_json(silent=True) or {}).get("method","cash")
    db.session.commit()
    return jsonify(serialize_order(order))

@app.route("/api/pos/table/<int:table_number>/active-order")
def api_table_active_order(table_number):
    if not api_staff_check(): return __import__("flask").jsonify({"error":"Unauthorized"}), 401
    order = Order.query.filter_by(table_number=table_number).filter(
        Order.status.in_(["confirmed","preparing","ready","served"])
    ).order_by(Order.created_at.desc()).first()
    if not order:
        return jsonify({"error":"No active order"}), 404
    return jsonify(serialize_order(order))

# ════════════════════════════════════════════
#  KITCHEN PANEL
# ════════════════════════════════════════════

@app.route("/kitchen")
@staff_required
def kitchen_panel():
    return render_template("kitchen.html", restaurant=get_restaurant_info(),
                           staff_name=session.get("staff_name",""))

@app.route("/api/kitchen/orders")
def api_kitchen_orders():
    # Allow if logged in via session OR if request comes from internal (127.0.0.1)
    if not session.get("staff_id") and get_real_ip() not in ("127.0.0.1","::1"):
        return jsonify({"error":"Unauthorized"}), 401
    orders = Order.query.filter(
        Order.status.in_(["confirmed","preparing","ready"])
    ).order_by(Order.created_at.asc()).all()
    return jsonify([serialize_order(o) for o in orders])

# ════════════════════════════════════════════
#  ADMIN PANEL
# ════════════════════════════════════════════

@app.route("/admin")

@app.route("/mb-console-2024/login", methods=["GET","POST"])
def admin_login_page():
    ip = get_real_ip()
    error = ""
    if is_rate_limited(ip):
        error = "Too many failed attempts. Try again in 15 minutes."
        return render_template("staff_login.html", restaurant=get_restaurant_info(), error=error, next_url="/mb-console-2024", admin_only=True)
    if request.method == "POST":
        username = request.form.get("username","").strip().lower()
        password = request.form.get("password","")
        user = StaffUser.query.filter_by(username=username, active=True).first()
        if user and user.check_password(password):
            if user.role not in ("admin","manager"):
                return render_template("staff_login.html", restaurant=get_restaurant_info(), error="Admin/Manager only.", next_url="/mb-console-2024", admin_only=True)
            record_success(ip)
            log_login(username, True, "/mb-console-2024")
            session.permanent = True
            session["staff_id"]   = user.id
            session["staff_name"] = user.username
            session["staff_role"] = user.role
            user.last_login = datetime.datetime.utcnow()
            db.session.commit()
            return redirect("/mb-console-2024")
        else:
            record_failed(ip)
            error = "Wrong username or password."
    return render_template("staff_login.html", restaurant=get_restaurant_info(), error=error, next_url="/mb-console-2024", admin_only=True)

@app.route("/mb-console-2024")
@admin_required
def admin_panel():
    items  = MenuItem.query.order_by(MenuItem.category, MenuItem.sort_order).all()
    today  = datetime.date.today()
    today_orders = Order.query.filter(db.func.date(Order.created_at)==today).all()
    paid_today   = [o for o in today_orders if o.payment_status=="paid"]
    today_sales  = sum(o.total for o in paid_today)
    pending_pay  = sum(1 for o in today_orders if o.payment_status=="unpaid")
    # 7-day trend
    trend = []
    max_trend = 1
    for i in range(6,-1,-1):
        d = today - datetime.timedelta(days=i)
        day_orders = Order.query.filter(
            db.func.date(Order.created_at)==d, Order.payment_status=="paid"
        ).all()
        val = sum(o.total for o in day_orders)
        trend.append({"label":d.strftime("%a"),"value":val})
        max_trend = max(max_trend, val)
    # category sales today
    cat_sales = {c:0 for c in get_category_order()}
    for o in paid_today:
        for i in o.items:
            item = db.session.get(MenuItem, i.menu_item_id)
            if item and item.category in cat_sales:
                cat_sales[item.category] += i.line_total
    max_cat = max(cat_sales.values()) if any(cat_sales.values()) else 1
    tables  = RestaurantTable.query.order_by(RestaurantTable.number).all()
    recent  = Order.query.order_by(Order.created_at.desc()).limit(15).all()
    invoices= Order.query.filter_by(payment_status="paid").order_by(Order.created_at.desc()).limit(50).all()
    plat    = Order.query.filter(Order.source.in_(["grab","foodpanda"])).order_by(Order.created_at.desc()).limit(30).all()
    waiters = Waiter.query.order_by(Waiter.name).all()
    addons  = AddOn.query.order_by(AddOn.name).all()
    cats    = Category.query.order_by(Category.sort_order).all()
    return render_template("admin.html",
        items=items, restaurant=get_restaurant_info(), settings=get_settings(),
        today_sales=today_sales, today_orders_count=len(today_orders),
        pending_payment=pending_pay, trend=trend, max_trend=max_trend,
        cat_sales=cat_sales, max_cat_sales=max_cat,
        tables=tables, recent_orders=recent,
        completed_invoices=invoices, platform_orders=plat,
        waiters=waiters, addons=addons,
        category_objs=cats, categories=get_category_order())


@app.route("/api/admin/table", methods=["POST"])
@admin_required
def api_admin_add_table():
    import secrets
    data = request.get_json(silent=True) or {}
    num  = int(data.get("number",0))
    label= data.get("label","") or f"Table {num}"
    if not num:
        return jsonify({"error":"Table number required"}), 400
    existing = RestaurantTable.query.filter_by(number=num).first()
    if existing:
        return jsonify({"error":"Table already exists"}), 400
    t = RestaurantTable(number=num, label=label, status="free", token=secrets.token_hex(8))
    db.session.add(t)
    db.session.commit()
    return jsonify({"ok":True,"id":t.id})

@app.route("/api/admin/table/<int:tid>/delete", methods=["POST"])
@admin_required
def api_admin_delete_table(tid):
    t = db.get_or_404(RestaurantTable, tid)
    db.session.delete(t)
    db.session.commit()
    return jsonify({"ok":True})

# ── Admin API routes ──


@app.route("/api/admin/menu-item/<int:iid>/toggle", methods=["POST"])
@admin_required
def api_admin_toggle_item(iid):
    item = db.get_or_404(MenuItem, iid)
    item.available = not item.available
    db.session.commit()
    return jsonify({"ok":True,"available":item.available})

@app.route("/api/admin/menu-item", methods=["POST"])
@admin_required
def api_admin_save_item():
    data    = request.get_json(silent=True) or {}
    item_id = data.get("id")
    item    = db.session.get(MenuItem, item_id) if item_id else MenuItem()
    if not item_id: db.session.add(item)
    item.category    = data.get("category","")
    item.name        = data.get("name","")
    item.price_full  = float(data.get("price_full") or 0)
    item.price_half  = float(data.get("price_half") or 0)
    item.description = data.get("description","")
    item.rating      = float(data.get("rating") or 4.5)
    images           = [u for u in (data.get("images") or []) if u]
    item.images_json = json.dumps(images)
    item.image_url   = images[0] if images else CATEGORY_IMAGES.get(item.category,"")
    item.available   = bool(data.get("available", True))
    db.session.commit()
    return jsonify({"ok":True,"id":item.id})

@app.route("/api/admin/menu-item/<int:iid>/delete", methods=["POST"])
@admin_required
def api_admin_delete_item(iid):
    db.session.delete(db.get_or_404(MenuItem, iid))
    db.session.commit()
    return jsonify({"ok":True})

@app.route("/api/admin/addon", methods=["POST"])
@admin_required
def api_admin_save_addon():
    data = request.get_json(silent=True) or {}
    aid  = data.get("id")
    a    = db.session.get(AddOn, aid) if aid else AddOn()
    if not aid: db.session.add(a)
    a.name      = data.get("name","")
    a.price     = float(data.get("price") or 0)
    a.image_url = data.get("image_url","")
    a.available = bool(data.get("available", True))
    db.session.commit()
    return jsonify({"ok":True,"id":a.id})

@app.route("/api/admin/addon/<int:aid>/delete", methods=["POST"])
@admin_required
def api_admin_delete_addon(aid):
    db.session.delete(db.get_or_404(AddOn, aid))
    db.session.commit()
    return jsonify({"ok":True})

@app.route("/api/admin/category", methods=["POST"])
@admin_required
def api_admin_save_category():
    data    = request.get_json(silent=True) or {}
    cid     = data.get("id")
    cat     = db.session.get(Category, cid) if cid else Category()
    old_name= cat.name if cid else None
    if not cid: db.session.add(cat)
    cat.name      = data.get("name","").strip()
    cat.image_url = data.get("image_url","")
    if data.get("sort_order") is not None:
        cat.sort_order = int(data.get("sort_order") or 0)
    db.session.commit()
    if old_name and old_name != cat.name:
        for mi in MenuItem.query.filter_by(category=old_name).all():
            mi.category = cat.name
        db.session.commit()
    return jsonify({"ok":True,"id":cat.id})

@app.route("/api/admin/category/<int:cid>/delete", methods=["POST"])
@admin_required
def api_admin_delete_category(cid):
    cat = db.get_or_404(Category, cid)
    in_use = MenuItem.query.filter_by(category=cat.name).count()
    if in_use:
        return jsonify({"error":f"{in_use} item(s) still use this category"}), 400
    db.session.delete(cat)
    db.session.commit()
    return jsonify({"ok":True})

@app.route("/api/admin/settings", methods=["POST"])
@admin_required
def api_admin_settings():
    data = request.get_json(silent=True) or {}
    for k,v in data.items():
        row = SiteSetting.query.get(k)
        if not row: row = SiteSetting(key=k,value=""); db.session.add(row)
        row.value = v
    db.session.commit()
    return jsonify({"ok":True,"settings":get_settings()})

@app.route("/api/admin/waiter", methods=["POST"])
@admin_required
def api_admin_save_waiter():
    data = request.get_json(silent=True) or {}
    wid  = data.get("id")
    w    = db.session.get(Waiter, wid) if wid else Waiter()
    if not wid: db.session.add(w)
    w.name   = data.get("name","")
    w.pin    = data.get("pin","")
    w.active = bool(data.get("active", True))
    db.session.commit()
    return jsonify({"ok":True,"id":w.id})

@app.route("/api/admin/waiter/<int:wid>/delete", methods=["POST"])
@admin_required
def api_admin_delete_waiter(wid):
    db.session.delete(db.get_or_404(Waiter, wid))
    db.session.commit()
    return jsonify({"ok":True})

@app.route("/api/admin/table/<int:tid>/reset", methods=["POST"])
@admin_required
def api_admin_reset_table(tid):
    t = db.get_or_404(RestaurantTable, tid)
    t.status = "free"
    db.session.commit()
    return jsonify({"ok":True})

# ── Staff User Management ──

@app.route("/api/admin/staff", methods=["GET"])
@admin_required
def api_admin_staff_list():
    users = StaffUser.query.order_by(StaffUser.username).all()
    return jsonify([{"id":u.id,"username":u.username,"role":u.role,
                     "active":u.active,"last_login":u.last_login.strftime("%Y-%m-%d %H:%M") if u.last_login else ""} for u in users])

@app.route("/api/admin/staff", methods=["POST"])
@admin_required
def api_admin_save_staff():
    data = request.get_json(silent=True) or {}
    uid  = data.get("id")
    u    = db.session.get(StaffUser, uid) if uid else StaffUser()
    if not uid: db.session.add(u)
    u.username = data.get("username","").strip().lower()
    u.role     = data.get("role","staff")
    u.active   = bool(data.get("active", True))
    if data.get("password"):
        u.set_password(data["password"])
    elif not uid:
        return jsonify({"error":"Password required for new user"}), 400
    db.session.commit()
    return jsonify({"ok":True,"id":u.id})

@app.route("/api/admin/staff/<int:uid>/delete", methods=["POST"])
@admin_required
def api_admin_delete_staff(uid):
    u = db.get_or_404(StaffUser, uid)
    if u.role == "admin" and StaffUser.query.filter_by(role="admin",active=True).count() <= 1:
        return jsonify({"error":"Cannot delete last admin"}), 400
    db.session.delete(u)
    db.session.commit()
    return jsonify({"ok":True})

# ── IP Whitelist ──

@app.route("/api/admin/ip-whitelist", methods=["GET"])
@admin_required
def api_admin_ip_list():
    ips = IPWhitelist.query.order_by(IPWhitelist.added_at).all()
    current_ip = get_real_ip()
    return jsonify({"ips":[{"id":i.id,"ip":i.ip_address,"label":i.label} for i in ips],
                    "your_ip": current_ip})

@app.route("/api/admin/ip-whitelist", methods=["POST"])
@admin_required
def api_admin_add_ip():
    data = request.get_json(silent=True) or {}
    ip   = (data.get("ip") or "").strip()
    if not ip:
        return jsonify({"error":"IP required"}), 400
    exists = IPWhitelist.query.filter_by(ip_address=ip).first()
    if exists:
        return jsonify({"error":"IP already in list"}), 400
    db.session.add(IPWhitelist(ip_address=ip, label=data.get("label","")))
    db.session.commit()
    return jsonify({"ok":True})

@app.route("/api/admin/ip-whitelist/<int:wid>/delete", methods=["POST"])
@admin_required
def api_admin_delete_ip(wid):
    db.session.delete(db.get_or_404(IPWhitelist, wid))
    db.session.commit()
    return jsonify({"ok":True})

# ── Login Logs ──

@app.route("/api/admin/login-logs")
@admin_required
def api_admin_login_logs():
    logs = LoginLog.query.order_by(LoginLog.at.desc()).limit(100).all()
    return jsonify([{"username":l.username,"ip":l.ip_address,"success":l.success,
                     "path":l.path,"at":l.at.strftime("%Y-%m-%d %H:%M:%S")} for l in logs])

# ── Current session info ──

@app.route("/api/me")
def api_me():
    uid = session.get("staff_id")
    if not uid: return jsonify({"logged_in":False})
    u = db.session.get(StaffUser, uid)
    if not u: return jsonify({"logged_in":False})
    return jsonify({"logged_in":True,"username":u.username,"role":u.role})

# Image upload
UPLOAD_DIR = os.path.join(BASE_DIR, "static", "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)
ALLOWED_EXT = {"png","jpg","jpeg","webp","gif"}

@app.route("/api/admin/upload", methods=["POST"])
@admin_required
def api_admin_upload():
    f = request.files.get("file")
    if not f or not f.filename:
        return jsonify({"error":"No file"}), 400
    ext = f.filename.rsplit(".",1)[-1].lower() if "." in f.filename else ""
    if ext not in ALLOWED_EXT:
        return jsonify({"error":"Invalid file type"}), 400
    import uuid
    fname = f"{uuid.uuid4().hex}.{ext}"
    f.save(os.path.join(UPLOAD_DIR, fname))
    return jsonify({"ok":True,"url":url_for("static",filename=f"uploads/{fname}")})

# QR code with logo
@app.route("/admin/qr/<int:table_number>.png")
def table_qr(table_number):
    from PIL import Image, ImageDraw
    base = SITE_URL
    # Use secure token instead of plain table number
    t = RestaurantTable.query.filter_by(number=table_number).first()
    if t:
        if not t.token:
            import secrets
            t.token = secrets.token_hex(8)
            db.session.commit()
        url = f"{base}/order?t={t.token}"
    else:
        url = f"{base}/order?table={table_number}"
    
    qr = qrcode.QRCode(
        error_correction=qrcode.constants.ERROR_CORRECT_H,
        box_size=10, border=4
    )
    qr.add_data(url)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white").convert("RGB")
    
    # Add logo if exists
    logo_path = os.path.join(BASE_DIR, "static", "favicon.jpg")
    if not os.path.exists(logo_path):
        logo_path = os.path.join(BASE_DIR, "static", "favicon.ico")
    
    if os.path.exists(logo_path):
        try:
            logo = Image.open(logo_path).convert("RGBA")
            qr_w, qr_h = img.size
            logo_size = qr_w // 4
            logo = logo.resize((logo_size, logo_size), Image.LANCZOS)
            # Circular mask
            mask = Image.new("L", logo.size, 0)
            draw = ImageDraw.Draw(mask)
            draw.ellipse([0, 0, logo_size, logo_size], fill=255)
            logo.putalpha(mask)
            pos = ((qr_w - logo_size) // 2, (qr_h - logo_size) // 2)
            img.paste(logo, pos, logo)
        except Exception as e:
            pass  # Use plain QR if logo fails
    
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return send_file(buf, mimetype="image/png")

# CSV export
@app.route("/api/admin/export/orders.csv")
@admin_required
def api_export_orders():
    date_from = request.args.get("from")
    date_to   = request.args.get("to")
    source    = request.args.get("source")
    q = Order.query.order_by(Order.created_at.desc())
    if date_from:
        try: q = q.filter(Order.created_at >= datetime.datetime.fromisoformat(date_from))
        except Exception: pass
    if date_to:
        try: q = q.filter(Order.created_at <= datetime.datetime.fromisoformat(date_to+" 23:59:59"))
        except Exception: pass
    if source and source != "all":
        q = q.filter_by(source=source)
    orders = q.all()
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["Order No","Date","Source","Table","Customer","Waiter",
                "Subtotal","Tax","Service","Discount","Total",
                "Paid","Change","Method","Status","Items"])
    for o in orders:
        w.writerow([o.order_no, o.created_at.strftime("%Y-%m-%d %H:%M"),
                    o.source, o.table_number or "", o.customer_name, o.waiter_name,
                    o.subtotal, o.tax, o.service_charge or 0, o.discount_amount or 0, o.total,
                    o.customer_paid or 0, o.change_due or 0, o.payment_method, o.status,
                    " | ".join(f"{i.qty}x {i.name}({i.size})" for i in o.items)])
    resp = make_response(buf.getvalue())
    resp.headers["Content-Type"] = "text/csv"
    resp.headers["Content-Disposition"] = "attachment; filename=islamabad-restaurant-orders.csv"
    return resp

# Daily summary API
@app.route("/api/admin/daily-summary")
@admin_required
def api_daily_summary():
    date_str = request.args.get("date", datetime.date.today().isoformat())
    try: d = datetime.date.fromisoformat(date_str)
    except Exception: d = datetime.date.today()
    orders = Order.query.filter(db.func.date(Order.created_at)==d).all()
    paid   = [o for o in orders if o.payment_status=="paid"]
    return jsonify({
        "date": d.isoformat(),
        "total_orders": len(orders),
        "paid_orders": len(paid),
        "total_sales": round(sum(o.total for o in paid),2),
        "total_discount": round(sum(o.discount_amount or 0 for o in paid),2),
        "by_source": {
            src: {"count": sum(1 for o in paid if o.source==src),
                  "total": round(sum(o.total for o in paid if o.source==src),2)}
            for src in ["pos","qr","online","grab","foodpanda"]
        },
        "by_method": {
            m: round(sum(o.total for o in paid if o.payment_method==m),2)
            for m in ["cash","card","fpx","ewallet","platform"]
        }
    })

# Platform orders (Grab / FoodPanda) — entered by staff, not a real
# webhook from those platforms, so it needs the same staff auth as POS.
@app.route("/api/platform/order", methods=["POST"])
def api_platform_order():
    if not api_staff_check(): return jsonify({"error":"Unauthorized"}), 401
    data  = request.get_json(silent=True) or {}
    src   = data.get("source","grab")
    cart  = data.get("items",[])
    if not cart: return jsonify({"error":"No items"}), 400
    order = Order(
        order_no=next_order_no(), order_type="delivery",
        customer_name=data.get("customer_name",""),
        customer_phone=data.get("customer_phone",""),
        platform_order_id=data.get("platform_order_id",""),
        notes=data.get("notes",""),
        status="confirmed", payment_method="platform",
        payment_status="paid", source=src,
    )
    subtotal = build_order_items(cart, order)
    order.subtotal = subtotal
    order.tax      = 0
    order.total    = subtotal
    db.session.add(order)
    db.session.commit()
    return jsonify(serialize_order(order))

# Menu / addons public APIs
@app.route("/api/menu-items")
def api_menu_items():
    items = MenuItem.query.filter_by(available=True).order_by(MenuItem.sort_order).all()
    return jsonify([{"id":i.id,"category":i.category,"name":i.name,
                     "price_full":i.price_full,"price_half":i.price_half,
                     "image_url":i.image_url,"images":i.images,
                     "description":i.description,"rating":i.rating} for i in items])

@app.route("/api/addons")
def api_addons():
    return jsonify([{"id":a.id,"name":a.name,"price":a.price,"image_url":a.image_url}
                    for a in AddOn.query.filter_by(available=True).all()])

# ════════════════════════════════════════════
#  HITPAY INTEGRATION
# ════════════════════════════════════════════

def hitpay_api_url(path):
    base = "https://api.sandbox.hit-pay.com" if app.config["HITPAY_SANDBOX"] else "https://api.hit-pay.com"
    return f"{base}{path}"

def hitpay_headers():
    return {
        "X-BUSINESS-API-KEY": app.config["HITPAY_API_KEY"],
        "Content-Type": "application/x-www-form-urlencoded",
        "X-Requested-With": "XMLHttpRequest",
    }
@app.route("/api/hitpay/webhook", methods=["POST"])
def api_hitpay_webhook():
    """
    HitPay calls this URL after payment completes.
    Register this URL in HitPay Dashboard → Developers → Webhook Endpoints.
    """
    raw_body = request.get_data(as_text=True)
    received_hmac = request.form.get("hmac", "")

    # Verify HMAC signature (fail closed — reject if not configured or invalid)
    _, salt, _ = _hitpay_config()
    if not salt:
        app.logger.error("HitPay webhook rejected: HITPAY_SALT not configured")
        return "Webhook not configured", 500
    if not received_hmac or not hitpay_verify_webhook(raw_body, received_hmac, salt):
        return "Invalid signature", 400

    payment_request_id = request.form.get("payment_request_id", "")
    reference_number   = request.form.get("reference_number", "")   # = our order_no
    status             = request.form.get("status", "")
    payment_id         = request.form.get("payment_id", "")
    payment_type       = request.form.get("payment_type", "")
    amount             = request.form.get("amount", "0")

    # Find our order
    order = Order.query.filter_by(order_no=reference_number).first()
    if not order:
        # Try by hitpay notes
        order = Order.query.filter(Order.notes.like(f"hitpay:{payment_request_id}%")).first()
    if not order:
        return "Order not found", 404

    if status == "completed":
        order.payment_status = "paid"
        order.payment_method = payment_type or order.payment_method
        order.status         = "confirmed"
        order.customer_paid  = float(amount)
        # Mark table occupied if applicable
        if order.table_number:
            t = RestaurantTable.query.filter_by(number=order.table_number).first()
            if t: t.status = "occupied"
        db.session.commit()

    return "OK", 200


@app.route("/api/hitpay/status/<order_no>")
def api_hitpay_status(order_no):
    """Polling endpoint — frontend polls this after redirect back from HitPay."""
    order = Order.query.filter_by(order_no=order_no).first_or_404()
    return jsonify({
        "order_no":       order.order_no,
        "payment_status": order.payment_status,
        "status":         order.status,
        "total":          order.total,
    })


@app.route("/api/admin/hitpay/configure", methods=["POST"])
@admin_required
def api_admin_hitpay_configure():
    """Save HitPay API key + salt to site settings (persisted in DB)."""
    data = request.get_json(silent=True) or {}
    for k in ["hitpay_api_key", "hitpay_salt", "hitpay_sandbox"]:
        if k in data:
            row = SiteSetting.query.get(k)
            if not row:
                row = SiteSetting(key=k, value=""); db.session.add(row)
            row.value = str(data[k])
    db.session.commit()
    # Also push to in-process config (takes effect immediately without restart)
    if "hitpay_api_key" in data:
        app.config["HITPAY_API_KEY"]  = data["hitpay_api_key"]
    if "hitpay_salt" in data:
        app.config["HITPAY_SALT"]     = data["hitpay_salt"]
    if "hitpay_sandbox" in data:
        app.config["HITPAY_SANDBOX"]  = str(data["hitpay_sandbox"]).lower() == "true"
    return jsonify({"ok": True})


# Bill


@app.route("/customer-display")
@staff_required
def customer_display():
    return render_template("customer_display.html", restaurant=get_restaurant_info(), settings=get_settings())

@app.route("/token/<int:oid>")
@staff_required
def token_slip(oid):
    order = db.get_or_404(Order, oid)
    return render_template("token_slip.html", order=order, restaurant=get_restaurant_info())

@app.route("/bill/<int:oid>")
@staff_required
def bill(oid):
    order = db.get_or_404(Order, oid)
    fmt   = request.args.get("format","a4")
    return render_template("bill.html", order=order,
                           restaurant=get_restaurant_info(), fmt=fmt, settings=get_settings())

# ════════════════════════════════════════════
#  DB MIGRATION + STARTUP
# ════════════════════════════════════════════

def migrate_db():
    """Add any missing columns/tables — safe, idempotent."""
    # Flask-SQLAlchemy resolves the relative sqlite:///maibistro.db URI
    # against the app's instance folder, not BASE_DIR directly.
    db_path = os.path.join(app.instance_path, "maibistro.db")
    if not os.path.exists(db_path):
        return
    try:
        conn = sqlite3.connect(db_path)
        cur  = conn.cursor()
        def cols(table):
            try: return {row[1] for row in cur.execute(f"PRAGMA table_info({table})")}
            except Exception: return set()
        def tables_exist():
            return {row[0] for row in cur.execute("SELECT name FROM sqlite_master WHERE type='table'")}

        # Order table columns
        o_cols = cols('"order"')
        for col, typ in [
            ("service_charge","REAL DEFAULT 0"),
            ("discount_type","VARCHAR(20) DEFAULT 'none'"),
            ("discount_value","REAL DEFAULT 0"),
            ("discount_amount","REAL DEFAULT 0"),
            ("customer_paid","REAL DEFAULT 0"),
            ("change_due","REAL DEFAULT 0"),
            ("waiter_name","VARCHAR(60) DEFAULT ''"),
            ("platform_order_id","VARCHAR(80) DEFAULT ''"),
            ("notes","VARCHAR(255) DEFAULT ''"),
            ("token_no","VARCHAR(10) DEFAULT ''"),
            ("takeaway_no","INTEGER"),
            ("master_key_used","BOOLEAN DEFAULT 0"),
            ("delivery_address","VARCHAR(255) DEFAULT ''"),
        ]:
            if col not in o_cols:
                try: cur.execute(f'ALTER TABLE "order" ADD COLUMN {col} {typ}')
                except Exception: pass

        # AddOn image
        a_cols = cols("add_on")
        if "image_url" not in a_cols:
            try: cur.execute("ALTER TABLE add_on ADD COLUMN image_url VARCHAR(255) DEFAULT ''")
            except Exception: pass

        # MenuItem extra fields
        m_cols = cols("menu_item")
        for col, typ in [("description","TEXT DEFAULT ''"),("images_json","TEXT DEFAULT '[]'"),("rating","REAL DEFAULT 4.5")]:
            if col not in m_cols:
                try: cur.execute(f"ALTER TABLE menu_item ADD COLUMN {col} {typ}")
                except Exception: pass

        # OrderItem addons
        oi_cols = cols("order_item")
        if "addons_json" not in oi_cols:
            try: cur.execute("ALTER TABLE order_item ADD COLUMN addons_json TEXT DEFAULT '[]'")
            except Exception: pass

        # Customer — address + email verification
        c_cols = cols("customer")
        for col, typ in [
            ("address","VARCHAR(255) DEFAULT ''"),
            ("email_verified","BOOLEAN DEFAULT 0"),
            ("verify_token","VARCHAR(64) DEFAULT ''"),
            ("verify_token_sent","DATETIME"),
        ]:
            if col not in c_cols:
                try: cur.execute(f"ALTER TABLE customer ADD COLUMN {col} {typ}")
                except Exception: pass

        # StaffUser table
        if "staff_user" not in tables_exist():
            cur.execute("""CREATE TABLE IF NOT EXISTS staff_user (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username VARCHAR(40) UNIQUE NOT NULL,
                password_hash VARCHAR(128) NOT NULL,
                role VARCHAR(20) DEFAULT 'staff',
                active BOOLEAN DEFAULT 1,
                created_at DATETIME,
                last_login DATETIME
            )""")

        # IPWhitelist table
        if "ip_whitelist" not in tables_exist():
            cur.execute("""CREATE TABLE IF NOT EXISTS ip_whitelist (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address VARCHAR(45) UNIQUE NOT NULL,
                label VARCHAR(60) DEFAULT '',
                added_at DATETIME
            )""")

        # LoginLog table
        if "login_log" not in tables_exist():
            cur.execute("""CREATE TABLE IF NOT EXISTS login_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username VARCHAR(40) DEFAULT '',
                ip_address VARCHAR(45) DEFAULT '',
                success BOOLEAN DEFAULT 0,
                path VARCHAR(80) DEFAULT '',
                at DATETIME
            )""")

        # FailedAttempt table
        if "failed_attempt" not in tables_exist():
            cur.execute("""CREATE TABLE IF NOT EXISTS failed_attempt (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address VARCHAR(45) NOT NULL,
                count INTEGER DEFAULT 1,
                locked_until DATETIME,
                updated_at DATETIME
            )""")

        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[MIGRATION] {e}")

with app.app_context():
    migrate_db()
    db.create_all()
    seed()
    # Startup runs in the gunicorn master before `--preload` forks workers;
    # without disposing here, forked workers inherit and share this same
    # live Postgres connection, corrupting the wire protocol under concurrent
    # use and causing intermittent 500s. Disposing leaves each worker to open
    # its own fresh connection on first request.
    db.engine.dispose()

if __name__ == "__main__":
    # Default to localhost-only: cloudflare-run.sh/.bat already tunnel
    # http://localhost:5000 to the internet, so binding 0.0.0.0 here would
    # needlessly expose the raw Flask port on the LAN/WAN, letting an
    # attacker bypass Cloudflare entirely and hit the app directly with
    # forged headers. Set HOST=0.0.0.0 explicitly if you really need LAN access.
    host = os.environ.get("HOST", "127.0.0.1")
    app.run(host=host, port=int(os.environ.get("PORT", 5000)), debug=False)
