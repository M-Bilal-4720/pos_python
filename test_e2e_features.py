"""
End-to-End Test Suite for Table QR Self-Ordering & Call Staff Features
Tests 1 through 7 covering all specifications.
"""
import json
from app import app, db, RestaurantTable, MenuItem, AddOn, Order, TableRequest, StaffUser

def run_tests():
    client = app.test_client()
    passed = 0
    total = 0

    def test(name, condition, detail=""):
        nonlocal passed, total
        total += 1
        if condition:
            passed += 1
            print(f"[PASS] Test {total}: {name}")
        else:
            print(f"[FAIL] Test {total}: {name} - {detail}")

    with app.app_context():
        # Setup: Ensure tables have tokens
        t1 = RestaurantTable.query.filter_by(number=1).first()
        assert t1 is not None, "Table 1 must exist"
        t1_token = t1.token
        t1.qr_enabled = True
        db.session.commit()

        # Find items for testing
        item1 = MenuItem.query.filter_by(available=True).first()
        addon1 = AddOn.query.filter_by(available=True).first()

        print("\n==================================================")
        print("STARTING TEST SUITE: Table QR & Staff Call Bell")
        print("==================================================\n")

        # ----------------------------------------------------------------------
        # TEST 1: Table QR scan & Anonymous Self-Order Checkout
        # ----------------------------------------------------------------------
        print("--- TEST 1: Table QR Landing & Checkout ---")
        # 1.1 /table/<token> redirect
        res = client.get(f"/table/{t1_token}")
        test("Table QR entry redirects to /order?t=...", res.status_code == 302 and f"t={t1_token}" in res.location)

        # 1.2 /order?t=<token> loads without login
        res = client.get(f"/order?t={t1_token}")
        test("Menu loads without login for table QR session", res.status_code == 200 and b"Table 1" in res.data)
        test("Menu contains Call Staff button", b"Call Staff" in res.data)

        # 1.3 Anonymous table checkout
        checkout_payload = {
            "table_token": t1_token,
            "table_number": 1,
            "customer_name": "", # empty name should default to Table 1 Guest
            "customer_phone": "",
            "payment_method": "cash",
            "cart": [
                {
                    "id": item1.id,
                    "size": "full",
                    "qty": 2,
                    "addons": [],
                    "notes": "Extra crispy"
                }
            ]
        }
        res = client.post("/api/checkout", data=json.dumps(checkout_payload), content_type="application/json")
        data = res.get_json()
        test("Anonymous table checkout succeeds", res.status_code == 200 and "order_no" in data)
        order1_no = data.get("order_no")

        # Verify DB order record
        order1 = Order.query.filter_by(order_no=order1_no).first()
        test("Order source is 'customer_qr'", order1.source == "customer_qr")
        test("Order customer_name defaults to 'Table 1 Guest'", order1.customer_name == "Table 1 Guest")
        test("Order table_number is 1", order1.table_number == 1)
        test("Table status updated to 'occupied'", RestaurantTable.query.filter_by(number=1).first().status == "occupied")

        # ----------------------------------------------------------------------
        # TEST 2: Server-Side Price Calculation & Tamper Resistance
        # ----------------------------------------------------------------------
        print("\n--- TEST 2: Pricing Security ---")
        # Attempt to forge item price to RM 0.01
        forged_payload = {
            "table_token": t1_token,
            "table_number": 1,
            "customer_name": "Price Tamperer",
            "payment_method": "cash",
            "cart": [
                {
                    "id": item1.id,
                    "price": 0.01, # FORGED PRICE
                    "size": "full",
                    "qty": 1,
                    "addons": [{"name": addon1.name, "price": 0.00}] if addon1 else [] # FORGED ADDON PRICE
                }
            ]
        }
        res = client.post("/api/checkout", data=json.dumps(forged_payload), content_type="application/json")
        data = res.get_json()
        forged_order = Order.query.filter_by(order_no=data.get("order_no")).first()
        
        expected_base = item1.price_full or item1.price_half or 0
        expected_addon = addon1.price if addon1 else 0
        expected_subtotal = expected_base + expected_addon
        test("Server strictly ignores forged client prices and calculates from DB",
             abs(forged_order.subtotal - expected_subtotal) < 0.01,
             f"Expected subtotal RM {expected_subtotal}, got RM {forged_order.subtotal}")

        # ----------------------------------------------------------------------
        # TEST 3: Call Staff Workflow (Customer Request -> POS Alert -> Complete)
        # ----------------------------------------------------------------------
        print("\n--- TEST 3: Customer Call Staff System ---")
        call_payload = {
            "table_token": t1_token,
            "table_number": 1,
            "request_type": "water",
            "message": "2 glasses of iced water please"
        }
        res = client.post("/api/table/request", data=json.dumps(call_payload), content_type="application/json")
        call_data = res.get_json()
        test("Table request created successfully", res.status_code == 200 and call_data.get("ok") is True)
        req_id = call_data["request"]["id"]

        # Customer polls status
        res = client.get(f"/api/table/requests/{t1_token}")
        reqs = res.get_json()
        test("Customer can fetch table requests", len(reqs) > 0 and reqs[0]["id"] == req_id)
        test("Initial status is 'pending'", reqs[0]["status"] == "pending")

        # Staff POS auth session
        with client.session_transaction() as sess:
            sess["staff_id"] = 1
            sess["staff_name"] = "Staff Alex"
            sess["staff_role"] = "admin"

        # Staff POS checks table requests
        res = client.get("/api/pos/table-requests")
        pos_calls = res.get_json()
        test("POS receives incoming table request", any(r["id"] == req_id for r in pos_calls))

        # Staff acknowledges request ("on the way")
        res = client.post(f"/api/pos/table-request/{req_id}/status", data=json.dumps({"status": "acknowledged"}), content_type="application/json")
        test("Staff acknowledges request", res.status_code == 200)

        # Verify customer sees "acknowledged"
        res = client.get(f"/api/table/requests/{t1_token}")
        test("Customer receives 'acknowledged' status update", res.get_json()[0]["status"] == "acknowledged")

        # Staff marks completed
        res = client.post(f"/api/pos/table-request/{req_id}/status", data=json.dumps({"status": "completed"}), content_type="application/json")
        test("Staff marks request completed", res.status_code == 200)
        res = client.get(f"/api/table/requests/{t1_token}")
        test("Customer sees 'completed' status", res.get_json()[0]["status"] == "completed")

        # ----------------------------------------------------------------------
        # TEST 4: Quick Water Menu Item API & Direct Ordering
        # ----------------------------------------------------------------------
        print("\n--- TEST 4: Quick Water Menu Item & Direct Ordering ---")
        res = client.get("/api/menu/water-item")
        water_data = res.get_json()
        test("Water menu item endpoint returns valid item", res.status_code == 200 and water_data.get("ok") is True)
        water_id = water_data.get("id")

        water_order_payload = {
            "table_token": t1_token,
            "table_number": 1,
            "customer_name": "Water Guest",
            "payment_method": "cash",
            "cart": [
                {
                    "id": water_id,
                    "size": "full",
                    "qty": 3,
                    "addons": [],
                    "notes": "Cold"
                }
            ]
        }
        res = client.post("/api/checkout", data=json.dumps(water_order_payload), content_type="application/json")
        test("Direct water order checkout succeeds", res.status_code == 200 and "order_no" in res.get_json())

        # ----------------------------------------------------------------------
        # TEST 5: Multiple Customers at Same Table (Independent Orders)
        # ----------------------------------------------------------------------
        print("\n--- TEST 5: Multi-Customer Independent Ordering at Same Table ---")
        client2 = app.test_client()
        res2 = client2.get(f"/order?t={t1_token}")
        test("Second customer at Table 1 accesses menu independently", res2.status_code == 200)

        cust2_payload = {
            "table_token": t1_token,
            "table_number": 1,
            "customer_name": "Friend at Table 1",
            "payment_method": "cash",
            "cart": [{"id": item1.id, "size": "half" if item1.price_half else "full", "qty": 1, "addons": []}]
        }
        res2_order = client2.post("/api/checkout", data=json.dumps(cust2_payload), content_type="application/json")
        test("Second customer places independent order for Table 1", res2_order.status_code == 200)

        # ----------------------------------------------------------------------
        # TEST 6: Security, Table QR Enable/Disable & Token Regeneration
        # ----------------------------------------------------------------------
        print("\n--- TEST 6: Security & Admin Controls ---")
        # 6.1 Fake / Altered Table Number with valid token
        tampered_table_payload = {
            "table_token": t1_token, # Table 1 token
            "table_number": 99,       # Tampered table number!
            "customer_name": "Hacker",
            "payment_method": "cash",
            "cart": [{"id": item1.id, "size": "full", "qty": 1}]
        }
        res = client.post("/api/checkout", data=json.dumps(tampered_table_payload), content_type="application/json")
        data = res.get_json()
        tampered_order = Order.query.filter_by(order_no=data.get("order_no")).first()
        test("Backend forces table number from secure token (rejecting tampered 99)", tampered_order.table_number == 1)

        # 6.2 Admin disables QR for Table 1
        res = client.post(f"/api/admin/table/{t1.id}/toggle-qr", data=json.dumps({"enabled": False}), content_type="application/json")
        test("Admin can disable QR ordering for table", res.status_code == 200 and res.get_json().get("qr_enabled") is False)

        # Checkout while QR disabled must fail with 403
        res = client.post("/api/checkout", data=json.dumps(checkout_payload), content_type="application/json")
        test("Checkout rejected with 403 when table QR is disabled", res.status_code == 403)

        # Staff bell while QR disabled must fail with 403
        res = client.post("/api/table/request", data=json.dumps(call_payload), content_type="application/json")
        test("Staff call rejected with 403 when table QR is disabled", res.status_code == 403)

        # Re-enable QR for Table 1
        client.post(f"/api/admin/table/{t1.id}/toggle-qr", data=json.dumps({"enabled": True}), content_type="application/json")

        # 6.3 Admin regenerates token
        old_token = t1.token
        res = client.post(f"/api/admin/table/{t1.id}/regenerate-token")
        new_token = res.get_json().get("token")
        test("Admin regenerates table token", res.status_code == 200 and new_token != old_token)

        # Old token fails with 403
        old_token_payload = dict(checkout_payload)
        old_token_payload["table_token"] = old_token
        res = client.post("/api/checkout", data=json.dumps(old_token_payload), content_type="application/json")
        test("Old regenerated token is rejected with 403", res.status_code == 403)

        # ----------------------------------------------------------------------
        # TEST 7: Regression Testing (POS, Kitchen, Admin Print, Audit Log)
        # ----------------------------------------------------------------------
        print("\n--- TEST 7: Regression Testing & Printable Sheets ---")
        # POS orders fetch
        res = client.get("/api/pos/orders")
        test("POS orders API returns active orders", res.status_code == 200)

        # Kitchen orders fetch
        res = client.get("/api/kitchen/orders")
        test("Kitchen orders API returns active tickets", res.status_code == 200)

        # Admin table QR print single
        res = client.get("/admin/table/1/print")
        test("Admin single table QR print card renders", res.status_code == 200 and b"TABLE 1" in res.data)

        # Admin tables print all
        res = client.get("/admin/tables/print-all")
        test("Admin all-tables print sheet renders", res.status_code == 200 and b"Table QR Stand Cards" in res.data)

        # Admin table requests audit log API
        res = client.get("/api/admin/table-requests")
        test("Admin table requests audit API returns records", res.status_code == 200 and len(res.get_json()) > 0)

        # Customer tracking page
        res = client.get(f"/customer/track/{order1_no}")
        test("Customer tracking page renders for table order", res.status_code == 200 and b"Table 1" in res.data)

        print("\n==================================================")
        print(f"RESULTS: {passed}/{total} tests passed ({passed/total*100:.1f}%)")
        print("==================================================\n")
        assert passed == total, f"Some tests failed! {total - passed} failures."

if __name__ == "__main__":
    run_tests()
