"""
admin.py  -  Standalone Admin Panel (admin.html) + Plans system + FamGateway (famgateway.in) auto-verify.

app.py ke end me judta hai (autopay ki tarah):
    import admin
    admin.init(app, sys.modules[__name__])

Kya milta hai:
  - /admin            -> standalone admin.html (apna login screen)
  - /admin.php?action=login|logout|status|stats|users|user_set|user_delete|
                         plans|plan_save|plan_delete|orders|settings_get|settings_save
    Ye sab SIRF fixed admin username/password se gate hote hain (regular user account se
    koi lena dena nahi - koi bhi normal user, chahe uska is_admin flag set ho, is panel
    me login nahi kar sakta. Sirf neeche diye ADMIN_USER / ADMIN_PASS se hi access milta hai).
  - plans table: admin jitne chahe plans bana sakta hai (name, price, duration, features)
  - plan_orders table: FamGateway ke through plan purchase orders track hote hain
  - settings table: FamGateway API key, site name waghera - admin panel se hi edit ho sakte hain
  - /index.php?action=plans_list / plan_checkout / plan_status (normal logged-in app users ke liye)
  - /famgateway/webhook  -> FamGateway se instant payment.success callback (HMAC verified)
"""
import hashlib
import hmac
import json
import os
import sqlite3
import time

from flask import Blueprint, Response, jsonify, request, session

import gateway as fg

M = None  # app.py module
bp = Blueprint("admin_panel", __name__)

# ---- Fixed admin credentials. Sirf ye login kar sakta hai - koi normal user account nahi. ----
ADMIN_USER = "shadow_papa"
ADMIN_PASS = "shadow93373"
ADMIN_SESS_KEY = "sh_admin_ok"

SCHEMA = """
CREATE TABLE IF NOT EXISTS plans(
  id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, price REAL NOT NULL,
  duration_days INTEGER NOT NULL, features TEXT NOT NULL DEFAULT '[]',
  active INTEGER NOT NULL DEFAULT 1, sort_order INTEGER NOT NULL DEFAULT 0, created INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS plan_orders(
  id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, plan_id INTEGER NOT NULL,
  fg_order_id TEXT NOT NULL UNIQUE, amount REAL NOT NULL, status TEXT NOT NULL DEFAULT 'pending',
  checkout_url TEXT, qr_url TEXT, upi_intent TEXT, utr TEXT, created INTEGER NOT NULL, paid_at INTEGER);
CREATE INDEX IF NOT EXISTS ix_po_user ON plan_orders(user_id, status);
CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT);
"""


class AErr(Exception):
    def __init__(self, msg, code=400):
        super().__init__(msg)
        self.msg, self.code = msg, code


def fail(msg, code=400):
    r = jsonify(ok=False, error=msg)
    r.status_code = code
    return r


def ok(**kw):
    kw["ok"] = True
    return jsonify(kw)


# ============================================================ settings helpers
def get_setting(key, default=""):
    r = M.db().execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
    return r["value"] if r and r["value"] is not None else default


def set_setting(key, value):
    M.db().execute("INSERT INTO settings(key,value) VALUES(?,?) "
                   "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, str(value)))
    M.db().commit()


def gateway_key():
    k = get_setting("famgateway_api_key", "")
    return k or M.env("FAMGATEWAY_API_KEY", "")


# ============================================================ fixed-credential admin auth
def admin_logged_in():
    return bool(session.get(ADMIN_SESS_KEY))


def require_admin(fn):
    def wrap(*a, **kw):
        if not admin_logged_in():
            return fail("Admin login required.", 401)
        try:
            return fn(*a, **kw)
        except AErr as e:
            return fail(e.msg, e.code)
    wrap.__name__ = fn.__name__
    return wrap


def a_admin_login():
    b = M.body()
    user = str(b.get("username", "")).strip()
    pw = str(b.get("password", ""))
    ip_key = "adminlogin:" + M.client_ip()
    if M.blocked(ip_key, 8, 600):
        return fail("Too many failed attempts. Please wait a few minutes.", 429)
    good = hmac.compare_digest(user, ADMIN_USER) and hmac.compare_digest(pw, ADMIN_PASS)
    if not good:
        M.record(ip_key)
        return fail("Invalid username or password.", 401)
    session[ADMIN_SESS_KEY] = True
    session.permanent = True
    return ok(message="Logged in.")


def a_admin_logout():
    session.pop(ADMIN_SESS_KEY, None)
    return ok(message="Logged out.")


def a_admin_status():
    return ok(logged_in=admin_logged_in())


def plan_public(p):
    try:
        feats = json.loads(p["features"]) if p["features"] else []
    except ValueError:
        feats = []
    return {"id": p["id"], "name": p["name"], "price": M.num(p["price"]),
            "duration_days": p["duration_days"], "features": feats,
            "active": bool(p["active"]), "sort_order": p["sort_order"]}


# ============================================================ admin: dashboard stats
@require_admin
def a_admin_stats():
    d, now = M.db(), int(time.time())
    day0 = now - (now % 86400)
    users_c = d.execute("SELECT COUNT(*) c FROM users").fetchone()["c"]
    active_subs = d.execute("SELECT COUNT(*) c FROM users WHERE sub_end>?", (now,)).fetchone()["c"]
    plans_c = d.execute("SELECT COUNT(*) c FROM plans WHERE active=1").fetchone()["c"]
    plan_rev = d.execute("SELECT COALESCE(SUM(amount),0) t, COUNT(*) c FROM plan_orders WHERE status='success'").fetchone()
    today_rev = d.execute("SELECT COALESCE(SUM(amount),0) t, COUNT(*) c FROM plan_orders "
                          "WHERE status='success' AND paid_at>=?", (day0,)).fetchone()
    gw_rev = d.execute("SELECT COALESCE(SUM(amount),0) t FROM transactions").fetchone()["t"]
    pending_orders = d.execute("SELECT COUNT(*) c FROM plan_orders WHERE status='pending' AND created>?",
                               (now - 3600,)).fetchone()["c"]
    today_signups = d.execute("SELECT COUNT(*) c FROM users WHERE created>=?", (day0,)).fetchone()["c"]
    return ok(stats={
        "total_users": users_c, "active_subscriptions": active_subs, "active_plans": plans_c,
        "plan_revenue_total": M.num(plan_rev["t"]), "plan_orders_paid": plan_rev["c"],
        "plan_revenue_today": M.num(today_rev["t"]), "plan_orders_today": today_rev["c"],
        "gateway_revenue_total": M.num(gw_rev), "pending_orders": pending_orders,
        "today_signups": today_signups})


# ============================================================ admin: users
@require_admin
def a_admin_users():
    q = str(request.args.get("q", "")).strip()
    rows = (M.db().execute(
        "SELECT u.*, p.name AS plan_name FROM users u LEFT JOIN plans p ON p.id=u.plan_id "
        "WHERE u.email LIKE ? OR u.name LIKE ? ORDER BY u.id DESC LIMIT 300",
        ("%%%s%%" % q, "%%%s%%" % q)).fetchall())
    now = int(time.time())
    return ok(users=[{
        "id": r["id"], "name": r["name"], "email": r["email"], "created": M.ts_iso(r["created"]),
        "sub_end": M.ts_iso(r["sub_end"]), "active": bool(r["sub_end"] and r["sub_end"] > now),
        "is_admin": bool(r["is_admin"]), "banned": bool(r["banned"]), "plan_name": r["plan_name"]}
        for r in rows])


@require_admin
def a_admin_user_set():
    b = M.body()
    try:
        uid = int(b.get("user_id"))
    except (TypeError, ValueError):
        raise AErr("user_id required.")
    target = M.db().execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    if not target:
        raise AErr("User not found.", 404)
    if "is_admin" in b:
        M.db().execute("UPDATE users SET is_admin=? WHERE id=?", (1 if b["is_admin"] else 0, uid))
    if "banned" in b:
        M.db().execute("UPDATE users SET banned=? WHERE id=?", (1 if b["banned"] else 0, uid))
    if b.get("extend_days"):
        try:
            days = int(b["extend_days"])
        except (TypeError, ValueError):
            raise AErr("extend_days galat hai.")
        now = int(time.time())
        base = target["sub_end"] if (target["sub_end"] or 0) > now else now
        new_end = base + days * 86400
        M.db().execute("UPDATE users SET sub_start=COALESCE(sub_start,?), sub_end=? WHERE id=?",
                       (now, new_end, uid))
    if "set_plan_id" in b:
        pid = b["set_plan_id"] or None
        M.db().execute("UPDATE users SET plan_id=? WHERE id=?", (pid, uid))
    M.db().commit()
    return ok(message="User updated.")


@require_admin
def a_admin_user_delete():
    b = M.body()
    try:
        uid = int(b.get("user_id"))
    except (TypeError, ValueError):
        raise AErr("user_id required.")
    M.db().execute("DELETE FROM users WHERE id=?", (uid,))
    M.db().commit()
    return ok(message="User deleted.")


# ============================================================ admin: plans CRUD
@require_admin
def a_admin_plans():
    rows = M.db().execute("SELECT * FROM plans ORDER BY sort_order, id").fetchall()
    return ok(plans=[plan_public(p) for p in rows])


@require_admin
def a_admin_plan_save():
    b = M.body()
    name = str(b.get("name", "")).strip()[:80]
    if not name:
        raise AErr("Plan name required.")
    try:
        price = round(float(b.get("price")), 2)
    except (TypeError, ValueError):
        raise AErr("Valid price required.")
    if price <= 0 or price > 1000000:
        raise AErr("Price 0 se 1000000 ke beech honi chahiye.")
    try:
        days = int(b.get("duration_days"))
    except (TypeError, ValueError):
        raise AErr("Valid duration_days required.")
    if days < 1 or days > 3650:
        raise AErr("duration_days 1 se 3650 ke beech hona chahiye.")
    feats = b.get("features")
    if isinstance(feats, str):
        feats = [x.strip() for x in feats.split("\n") if x.strip()]
    elif isinstance(feats, list):
        feats = [str(x).strip() for x in feats if str(x).strip()]
    else:
        feats = []
    active = 1 if b.get("active", True) else 0
    try:
        sort_order = int(b.get("sort_order") or 0)
    except (TypeError, ValueError):
        sort_order = 0
    pid = b.get("id")
    if pid:
        M.db().execute("UPDATE plans SET name=?,price=?,duration_days=?,features=?,active=?,sort_order=? WHERE id=?",
                       (name, price, days, json.dumps(feats), active, sort_order, int(pid)))
    else:
        M.db().execute("INSERT INTO plans(name,price,duration_days,features,active,sort_order,created) "
                       "VALUES(?,?,?,?,?,?,?)",
                       (name, price, days, json.dumps(feats), active, sort_order, int(time.time())))
    M.db().commit()
    return ok(message="Plan saved.")


@require_admin
def a_admin_plan_delete():
    b = M.body()
    try:
        pid = int(b.get("id"))
    except (TypeError, ValueError):
        raise AErr("id required.")
    M.db().execute("DELETE FROM plans WHERE id=?", (pid,))
    M.db().execute("UPDATE users SET plan_id=NULL WHERE plan_id=?", (pid,))
    M.db().commit()
    return ok(message="Plan deleted.")


# ============================================================ admin: orders feed
@require_admin
def a_admin_orders():
    rows = M.db().execute(
        "SELECT o.*, pl.name AS plan_name, us.email AS user_email FROM plan_orders o "
        "LEFT JOIN plans pl ON pl.id=o.plan_id LEFT JOIN users us ON us.id=o.user_id "
        "ORDER BY o.id DESC LIMIT 200").fetchall()
    return ok(orders=[{
        "fg_order_id": r["fg_order_id"], "user_email": r["user_email"], "plan_name": r["plan_name"],
        "amount": M.num(r["amount"]), "status": r["status"], "utr": r["utr"],
        "created": M.ts_iso(r["created"]), "paid_at": M.ts_iso(r["paid_at"])} for r in rows])


# ============================================================ admin: settings
@require_admin
def a_admin_settings_get():
    key = gateway_key()
    masked = (key[:10] + "..." + key[-4:]) if len(key) > 16 else key
    return ok(settings={
        "famgateway_api_key_set": bool(key), "famgateway_api_key_masked": masked,
        "site_name": get_setting("site_name", "Fam Pay"),
        "require_subscription": M.REQUIRE_SUB})


@require_admin
def a_admin_settings_save():
    b = M.body()
    if "famgateway_api_key" in b and str(b["famgateway_api_key"]).strip():
        key = str(b["famgateway_api_key"]).strip()
        if not key.startswith("fam_") or len(key) < 10:
            raise AErr("FamGateway API key format galat lagta hai (fam_... se shuru honi chahiye).")
        set_setting("famgateway_api_key", key)
    if "site_name" in b:
        set_setting("site_name", str(b["site_name"]).strip()[:60] or "Fam Pay")
    return ok(message="Settings saved.")


# ============================================================ user-facing: plans + checkout
def a_plans_list(u):
    rows = M.db().execute("SELECT * FROM plans WHERE active=1 ORDER BY sort_order, price").fetchall()
    active, _, end = M.sub_state(u)
    cur_plan = None
    if u["plan_id"]:
        p = M.db().execute("SELECT * FROM plans WHERE id=?", (u["plan_id"],)).fetchone()
        cur_plan = plan_public(p) if p else None
    return ok(plans=[plan_public(p) for p in rows], current_plan=cur_plan,
              subscription_active=active, subscription_end=M.ts_iso(end) if active else None)


def a_plan_checkout(u):
    b = M.body()
    try:
        plan_id = int(b.get("plan_id"))
    except (TypeError, ValueError):
        return fail("plan_id required.")
    plan = M.db().execute("SELECT * FROM plans WHERE id=? AND active=1", (plan_id,)).fetchone()
    if not plan:
        return fail("Plan not found.", 404)
    key = gateway_key()
    if not key:
        return fail("Payment gateway abhi configure nahi hui hai. Admin se contact karo.", 503)
    if M.throttle("plancheck:%d" % u["id"], 10, 120):
        return fail("Too many attempts. Please wait a minute.", 429)
    redirect_url = M.base_url() + "/index.php#/plans"
    try:
        order = fg.create_order(key, plan["price"], redirect_url=redirect_url,
                                customer_name=u["name"], customer_email=u["email"])
    except fg.GatewayError as e:
        M.app.logger.warning("famgateway create_order failed: %s", e)
        return fail(str(e), 502)
    oid = order.get("order_id")
    if not oid:
        return fail("FamGateway ne order id nahi diya.", 502)
    qr_url = order.get("qr_url") or fg.qr_image_url(oid)
    try:
        M.db().execute("INSERT INTO plan_orders(user_id,plan_id,fg_order_id,amount,status,checkout_url,qr_url,"
                       "upi_intent,created) VALUES(?,?,?,?,?,?,?,?,?)",
                       (u["id"], plan_id, oid, plan["price"], "pending",
                        order.get("checkout_url"), qr_url, order.get("upi_intent"), int(time.time())))
        M.db().commit()
    except sqlite3.IntegrityError:
        pass
    return ok(order={
        "fg_order_id": oid, "amount": M.num(plan["price"]), "qr_url": qr_url,
        "checkout_url": order.get("checkout_url"), "upi_intent": order.get("upi_intent"),
        "plan_name": plan["name"], "expires_at_ist": order.get("expires_at_ist")})


def _apply_plan_payment(d, user_id, plan, fg_order_id, utr, amount):
    """Idempotent: subscription extend + sub_payments insert + plan_orders mark success."""
    now = int(time.time())
    if d.execute("SELECT 1 FROM sub_payments WHERE utr=?", (utr,)).fetchone():
        d.execute("UPDATE plan_orders SET status='success', utr=?, paid_at=? "
                  "WHERE fg_order_id=? AND status!='success'", (utr, now, fg_order_id))
        d.commit()
        return
    u = d.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    old_end = u["sub_end"] or 0
    was_renewal = old_end > now
    new_end = (old_end if was_renewal else now) + plan["duration_days"] * 86400
    d.execute("UPDATE users SET sub_start=?, sub_end=?, plan_id=? WHERE id=?",
             (u["sub_start"] if was_renewal and u["sub_start"] else now, new_end, plan["id"], user_id))
    try:
        d.execute("INSERT INTO sub_payments(utr,user_id,order_id,amount,created) VALUES(?,?,?,?,?)",
                 (utr, user_id, fg_order_id, amount, now))
    except sqlite3.IntegrityError:
        pass
    d.execute("UPDATE plan_orders SET status='success', utr=?, paid_at=? WHERE fg_order_id=?",
             (utr, now, fg_order_id))
    d.commit()


def a_plan_status(u):
    b = M.body()
    oid = str(b.get("fg_order_id", "")).strip()
    if not oid:
        return fail("fg_order_id required.")
    row = M.db().execute("SELECT * FROM plan_orders WHERE fg_order_id=? AND user_id=?",
                         (oid, u["id"])).fetchone()
    if not row:
        return fail("Order not found.", 404)
    if row["status"] == "success":
        return ok(status="success", amount=M.num(row["amount"]), utr=row["utr"])
    key = gateway_key()
    if not key:
        return fail("Payment gateway configure nahi hai.", 503)
    if M.throttle("planstat:%d" % u["id"], 40, 60):
        return fail("Too many requests.", 429)
    try:
        st = fg.verify_order(key, oid)
    except fg.GatewayError as e:
        M.app.logger.warning("famgateway verify_order failed: %s", e)
        return ok(status="pending")
    if st.get("status") == "expired" and row["status"] == "pending":
        M.db().execute("UPDATE plan_orders SET status='expired' WHERE fg_order_id=?", (oid,))
        M.db().commit()
        return ok(status="expired")
    if not st.get("paid"):
        return ok(status="pending")
    plan = M.db().execute("SELECT * FROM plans WHERE id=?", (row["plan_id"],)).fetchone()
    if not plan:
        return fail("Plan no longer exists.", 410)
    utr = st.get("utr") or oid
    _apply_plan_payment(M.db(), u["id"], plan, oid, utr, st.get("amount") or row["amount"])
    fresh = M.db().execute("SELECT * FROM users WHERE id=?", (u["id"],)).fetchone()
    _, _, end = M.sub_state(fresh)
    return ok(status="success", amount=M.num(st.get("amount") or row["amount"]), utr=utr,
              sender_name=st.get("sender_name"), plan_name=plan["name"],
              subscription_end=M.ts_iso(end))


# ============================================================ webhook (instant, optional)
@bp.post("/famgateway/webhook")
def famgateway_webhook():
    raw = request.get_data()
    sig = request.headers.get("X-FamGateway-Signature", "")
    key = gateway_key()
    if not key:
        return jsonify(status="ignored"), 200
    expected = hmac.new(key.encode(), raw, hashlib.sha256).hexdigest()
    if not sig or not hmac.compare_digest(sig, expected):
        return jsonify(status="invalid signature"), 401
    try:
        payload = json.loads(raw.decode("utf-8", "replace"))
    except ValueError:
        return jsonify(status="bad json"), 400
    if payload.get("status") != "success" and payload.get("event") != "payment.success":
        return jsonify(status="ignored"), 200
    oid = payload.get("order_id")
    row = M.db().execute("SELECT * FROM plan_orders WHERE fg_order_id=?", (oid,)).fetchone()
    if not row or row["status"] == "success":
        return jsonify(status="ok"), 200
    plan = M.db().execute("SELECT * FROM plans WHERE id=?", (row["plan_id"],)).fetchone()
    if plan:
        utr = payload.get("utr") or oid
        _apply_plan_payment(M.db(), row["user_id"], plan, oid, utr, payload.get("amount") or row["amount"])
    return jsonify(status="ok"), 200


# ============================================================ standalone /admin.html panel
ADMIN_ACTIONS = {
    "login": (a_admin_login, "POST", False), "logout": (a_admin_logout, "POST", False),
    "status": (a_admin_status, "GET", False),
    "stats": (a_admin_stats, "GET", True), "users": (a_admin_users, "GET", True),
    "user_set": (a_admin_user_set, "POST", True), "user_delete": (a_admin_user_delete, "POST", True),
    "plans": (a_admin_plans, "GET", True), "plan_save": (a_admin_plan_save, "POST", True),
    "plan_delete": (a_admin_plan_delete, "POST", True), "orders": (a_admin_orders, "GET", True),
    "settings_get": (a_admin_settings_get, "GET", True), "settings_save": (a_admin_settings_save, "POST", True),
}


@bp.get("/admin")
def admin_page():
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "admin.html")
    if not os.path.exists(path):
        return fail("admin.html not found.", 404)
    with open(path, encoding="utf-8") as f:
        return Response(f.read(), mimetype="text/html")


@bp.route("/admin.php", methods=["GET", "POST"])
def admin_router():
    name = request.args.get("action", "")
    entry = ADMIN_ACTIONS.get(name)
    if not entry:
        return fail("Unknown action.", 404)
    fn, method, _needs_auth = entry
    if request.method != method:
        return fail("Method not allowed.", 405)
    return fn()


# ============================================================ wiring
def init(app, main_module):
    global M
    M = main_module
    c = sqlite3.connect(M.DB_PATH, timeout=15)
    c.executescript(SCHEMA)
    cols = {r[1] for r in c.execute("PRAGMA table_info(users)")}
    for col, ddl in (("is_admin", "INTEGER NOT NULL DEFAULT 0"), ("banned", "INTEGER NOT NULL DEFAULT 0"),
                     ("plan_id", "INTEGER")):
        if col not in cols:
            c.execute("ALTER TABLE users ADD COLUMN %s %s" % (col, ddl))
    c.commit()
    c.close()
    app.register_blueprint(bp)
    M.action("plans_list", methods=("GET",))(a_plans_list)
    M.action("plan_checkout")(a_plan_checkout)
    M.action("plan_status")(a_plan_status)
