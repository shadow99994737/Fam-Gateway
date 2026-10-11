"""
gateway.py  -  FamGateway (https://famgateway.in) REST client.

Plans system ke liye subscription payments isi external gateway se verify
hote hain (admin panel me set kiya hua api_key use hota hai -> DB settings
table, .env FAMGATEWAY_API_KEY fallback).

    import gateway as fg
    order = fg.create_order(amount=99, customer_name="Rahul", redirect_url="https://site/x")
    status = fg.verify_order(order["order_id"])
    if status["paid"]: ...
"""
import json
import os
import time
import urllib.error
import urllib.request

BASE_URL = os.getenv("FAMGATEWAY_BASE_URL", "https://famgateway.in").rstrip("/")
TIMEOUT = int(os.getenv("FAMGATEWAY_TIMEOUT", "20"))

__all__ = ["GatewayError", "create_order", "verify_order", "checkout_status", "qr_image_url"]


class GatewayError(Exception):
    """FamGateway API call fail hui (network, auth, ya business error)."""

    def __init__(self, message, code=None, status=None):
        super().__init__(message)
        self.message = message
        self.code = code        # HTTP status
        self.status = status    # response "status" field, e.g. "unauthorized"


def _request(method, path, api_key=None, params=None, json_body=None):
    url = BASE_URL + path
    if params:
        from urllib.parse import urlencode
        q = urlencode({k: v for k, v in params.items() if v is not None})
        if q:
            url += ("&" if "?" in url else "?") + q
    headers = {"Accept": "application/json",
               "User-Agent": "Mozilla/5.0 (compatible; FamPayServer/1.0; +https://famgateway.in)"}
    data = None
    if json_body is not None:
        headers["Content-Type"] = "application/json"
        data = json.dumps(json_body).encode()
    if api_key:
        headers["X-Api-Key"] = api_key
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            body = resp.read().decode("utf-8", "replace")
            code = resp.getcode()
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", "replace")
        code = e.code
    except urllib.error.URLError as e:
        raise GatewayError("FamGateway tak pahunch nahi paye: %s" % e.reason)
    except Exception as e:
        raise GatewayError("FamGateway request fail: %s" % e)
    try:
        payload = json.loads(body) if body else {}
    except ValueError:
        raise GatewayError("FamGateway se invalid response mila.", code=code)
    return payload, code


def create_order(api_key, amount, order_id=None, redirect_url=None, webhook_url=None,
                  customer_name=None, customer_email=None, customer_phone=None, retries=2):
    """POST /api/create-order -> dict with order_id, qr_url, checkout_url, upi_intent, payable_amount."""
    body = {"amount": round(float(amount), 2)}
    if order_id:
        body["order_id"] = order_id
    if redirect_url:
        body["redirect_url"] = redirect_url
    if webhook_url:
        body["webhook_url"] = webhook_url
    if customer_name:
        body["customer_name"] = customer_name[:120]
    if customer_email:
        body["customer_email"] = customer_email[:160]
    if customer_phone:
        body["customer_phone"] = customer_phone[:20]
    last_err = None
    for attempt in range(retries + 1):
        try:
            payload, code = _request("POST", "/api/create-order", api_key=api_key, json_body=body)
        except GatewayError as e:
            last_err = e
            time.sleep(0.6)
            continue
        if payload.get("status") == "success":
            return payload.get("data") or {}
        msg = payload.get("message") or "FamGateway order create nahi ho payi."
        if code == 401:
            raise GatewayError("FamGateway API key invalid ya revoke ho chuki hai.", code=401, status="unauthorized")
        if code == 403:
            # 403 ka matlab hamesha "suspended" nahi hota (Cloudflare/IP block bhi ho sakta hai) - asli message dikhao.
            real = (payload.get("message") or "").strip()
            raise GatewayError("FamGateway ne request reject ki (403)%s. Apna FamGateway account/API key check karo."
                               % (": " + real if real else ""), code=403, status="forbidden")
        if code and code >= 500:
            last_err = GatewayError(msg, code=code)
            time.sleep(0.6)
            continue
        raise GatewayError(msg, code=code, status=payload.get("status"))
    raise last_err or GatewayError("FamGateway order create nahi ho payi.")


def verify_order(api_key, order_id):
    """GET /api/verify-order.php -> normalized dict: paid, status, amount, utr, sender_name, transaction_id."""
    payload, code = _request("GET", "/api/verify-order.php", api_key=api_key, params={"order_id": order_id})
    status = payload.get("status")
    if status == "success":
        d = payload.get("data") or {}
        return {"paid": True, "status": "success", "order_id": d.get("order_id", order_id),
                "amount": d.get("amount"), "utr": d.get("utr"), "sender_name": d.get("sender_name"),
                "transaction_id": d.get("transaction_id"), "payment_time_ist": d.get("payment_time_ist")}
    if status in ("pending", None) and code not in (401, 403, 404):
        return {"paid": False, "status": "pending", "order_id": order_id}
    if status == "expired" or code == 408:
        return {"paid": False, "status": "expired", "order_id": order_id}
    if code == 401:
        raise GatewayError("FamGateway API key invalid hai.", code=401, status="unauthorized")
    if code == 404:
        return {"paid": False, "status": "not_found", "order_id": order_id}
    return {"paid": False, "status": status or "pending", "order_id": order_id}


def checkout_status(order_id):
    """GET /api/checkout-status.php - public, no api_key (safe for browser polling)."""
    payload, code = _request("GET", "/api/checkout-status.php", params={"order_id": order_id})
    status = payload.get("status", "pending")
    return {"paid": status == "success", "status": status, "utr": payload.get("utr"),
            "sender_name": payload.get("sender_name")}


def qr_image_url(order_id):
    return "%s/api/qr-image.php?order_id=%s" % (BASE_URL, order_id)
