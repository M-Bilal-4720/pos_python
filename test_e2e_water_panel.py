"""
Comprehensive E2E Test Suite for the Water Panel Module:
1. Water Staff Authentication & Permission Guards
2. Menu Listing for Water Staff
3. New Order Creation from Water Panel
4. Adding Items & Open Items to Existing Active Order
5. Open/Custom Item Support (name, price, qty, notes)
6. POS Real-time Water Alerts (polling, notification, acknowledgment)
7. Water Views: Active Orders, My Orders, Table Statuses & Order Timeline
8. Admin Water Panel: Staff User CRUD, Password Reset, and Activity Logs Audit
"""
import json
import unittest
from app import app, db, seed, Order, OrderItem, RestaurantTable, StaffUser, MenuItem, WaterActivityLog, WaterAlert

class TestWaterPanelE2E(unittest.TestCase):
    def setUp(self):
        app.config["TESTING"] = True
        app.config["WTF_CSRF_ENABLED"] = False
        self.client = app.test_client()

        with app.app_context():
            db.create_all()
            seed()

    def login(self, username, password):
        return self.client.post('/login', data={'username': username, 'password': password}, follow_redirects=True)

    def logout(self):
        return self.client.get('/logout', follow_redirects=True)

    # ════════════════════════════════════════════════════════════
    # 1. AUTHENTICATION & ACCESS CONTROL
    # ════════════════════════════════════════════════════════════

    def test_water_login_and_redirect(self):
        """Water staff login should succeed and redirect directly to /water."""
        res = self.login("water1", "water123")
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.request.path, "/water")
        self.assertIn(b"Water", res.data)

    def test_water_login_route_renders_mobile_login(self):
        """Visiting /water/login renders dedicated mobile-first login screen."""
        res = self.client.get('/water/login', follow_redirects=False)
        self.assertEqual(res.status_code, 200)
        self.assertIn(b"Water", res.data)
        self.assertIn(b"username", res.data)
        self.assertIn(b"password", res.data)

    def test_unauthorized_access_blocked(self):
        """Unauthenticated requests to /water or /api/water/* must redirect or return 401/403."""
        # Unauthenticated HTML page
        res = self.client.get('/water')
        self.assertEqual(res.status_code, 302)
        self.assertIn('/login', res.headers.get('Location', ''))

        # Unauthenticated API
        res = self.client.get('/api/water/menu')
        self.assertIn(res.status_code, [302, 401, 403])

    def test_kitchen_user_blocked_from_water_panel(self):
        """Kitchen user should not be allowed into /water or /api/water/order."""
        self.login("kitchen", "kitchen123")
        res = self.client.get('/water')
        self.assertNotEqual(res.status_code, 200)
        self.logout()

    # ════════════════════════════════════════════════════════════
    # 2. WATER MENU RETRIEVAL
    # ════════════════════════════════════════════════════════════

    def test_water_menu_api(self):
        """Logged in water user can fetch menu items with categories and addons."""
        self.login("water1", "water123")
        res = self.client.get('/api/water/menu')
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertIn("categories", data)
        self.assertIn("grouped", data)
        self.assertIn("items", data)
        self.assertIn("addons", data)
        self.assertGreater(len(data["items"]), 0)
        self.logout()

    # ════════════════════════════════════════════════════════════
    # 3. NEW ORDER CREATION VIA WATER PANEL
    # ════════════════════════════════════════════════════════════

    def test_create_water_order_with_standard_items(self):
        """Water staff can place an order for a table; source='water', logs activity and generates POS alert."""
        self.login("water1", "water123")

        with app.app_context():
            item = MenuItem.query.filter_by(available=True).first()
            self.assertIsNotNone(item, "At least one menu item should exist in seed data")
            item_id = item.id
            item_name = item.name
            item_price = float(item.price_full or 5.0)

        cart = [
            {"id": item_id, "name": item_name, "qty": 2, "price": item_price, "notes": "Cold"}
        ]
        payload = {
            "table_number": 5,
            "cart": cart,
            "notes": "Fast water service"
        }

        res = self.client.post('/api/water/order', data=json.dumps(payload), content_type='application/json')
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data.get("ok"))
        order_obj = data.get("order", {})
        order_id = order_obj.get("id")
        self.assertIsNotNone(order_id)

        with app.app_context():
            order = db.session.get(Order, order_id)
            self.assertIsNotNone(order)
            self.assertEqual(order.table_number, 5)
            self.assertEqual(order.source, "water")
            self.assertEqual(order.created_by, "water1")
            self.assertEqual(len(order.items), 1)
            self.assertEqual(order.items[0].qty, 2)

            # Check WaterActivityLog
            log = WaterActivityLog.query.filter_by(order_id=order_id, action="create_order").first()
            self.assertIsNotNone(log)
            self.assertEqual(log.username, "water1")
            self.assertEqual(log.table_number, 5)

            # Check WaterAlert for POS
            alert = WaterAlert.query.filter_by(order_id=order_id, alert_type="new_order").first()
            self.assertIsNotNone(alert)
            self.assertEqual(alert.table_number, 5)
            self.assertEqual(alert.status, "unread")

        self.logout()

    # ════════════════════════════════════════════════════════════
    # 4. ADD ITEMS & OPEN ITEMS TO EXISTING ACTIVE ORDER
    # ════════════════════════════════════════════════════════════

    def test_add_items_and_open_item_to_existing_order(self):
        """Water staff can append items (standard and custom open items) to an active order without duplicating."""
        # First, create an initial order as water staff
        self.login("water1", "water123")
        with app.app_context():
            item = MenuItem.query.filter_by(available=True).first()
            item_id = item.id
            item_price = float(item.price_full or 5.0)

        init_cart = [{"id": item_id, "qty": 1, "price": item_price}]
        res1 = self.client.post('/api/water/order', data=json.dumps({"table_number": 8, "cart": init_cart}), content_type='application/json')
        order_id = res1.get_json()["order"]["id"]

        with app.app_context():
            initial_order = db.session.get(Order, order_id)
            initial_total = float(initial_order.total)
            initial_item_count = len(initial_order.items)

        # Now, add 1 standard item + 1 custom open item
        add_cart = [
            {"id": item_id, "qty": 1, "price": item_price, "notes": "Extra chilled"},
            {"open_item": True, "name": "Special Fresh Lime Water", "price": 4.50, "qty": 2, "notes": "Less sugar"}
        ]
        payload = {"cart": add_cart, "notes": "Added from table request"}
        res2 = self.client.post(f'/api/water/order/{order_id}/add-items', data=json.dumps(payload), content_type='application/json')
        self.assertEqual(res2.status_code, 200)
        data2 = res2.get_json()
        self.assertTrue(data2.get("ok"))
        self.assertIn("Special Fresh Lime Water", data2.get("added_summary", ""))

        with app.app_context():
            updated_order = db.session.get(Order, order_id)
            # Order items count should have increased by 2
            self.assertEqual(len(updated_order.items), initial_item_count + 2)
            # Order total should have recalculated
            self.assertGreater(float(updated_order.total), initial_total)

            # Check open item attributes
            open_item = OrderItem.query.filter_by(order_id=order_id, name="Special Fresh Lime Water").first()
            self.assertIsNotNone(open_item)
            self.assertEqual(float(open_item.unit_price), 4.50)
            self.assertEqual(open_item.qty, 2)
            self.assertEqual(open_item.notes, "Less sugar")

            # Check WaterActivityLog
            log = WaterActivityLog.query.filter_by(order_id=order_id, action="add_items").first()
            self.assertIsNotNone(log)
            self.assertIn("Special Fresh Lime Water", log.items_detail)

            # Check WaterAlert for POS
            alert = WaterAlert.query.filter_by(order_id=order_id, alert_type="add_items").first()
            self.assertIsNotNone(alert)
            self.assertIn("Special Fresh Lime Water", alert.items_summary)

        self.logout()

    # ════════════════════════════════════════════════════════════
    # 5. POS REAL-TIME WATER ALERTS (POLL & ACK)
    # ════════════════════════════════════════════════════════════

    def test_pos_water_alerts_polling_and_ack(self):
        """POS receives unread water alerts and can acknowledge them."""
        # Water user creates an order
        self.login("water1", "water123")
        with app.app_context():
            item = MenuItem.query.filter_by(available=True).first()
        self.client.post('/api/water/order', data=json.dumps({"table_number": 3, "cart": [{"id": item.id, "qty": 1}]}), content_type='application/json')
        self.logout()

        # POS user polls alerts
        self.login("admin", "admin123")
        res = self.client.get('/api/pos/water-alerts')
        self.assertEqual(res.status_code, 200)
        alerts = res.get_json()
        self.assertIsInstance(alerts, list)
        self.assertGreater(len(alerts), 0)
        first_alert = alerts[0]
        alert_id = first_alert["id"]

        # Acknowledge the alert
        ack_res = self.client.post(f'/api/pos/water-alert/{alert_id}/ack')
        self.assertEqual(ack_res.status_code, 200)
        self.assertTrue(ack_res.get_json().get("ok"))

        # Verify alert is no longer unread
        with app.app_context():
            db_alert = db.session.get(WaterAlert, alert_id)
            self.assertEqual(db_alert.status, "acknowledged")
        self.logout()

    # ════════════════════════════════════════════════════════════
    # 6. WATER USER VIEWS: TABLES & ORDER TIMELINE
    # ════════════════════════════════════════════════════════════

    def test_water_tables_api(self):
        """Water staff can retrieve all tables with their active order info."""
        self.login("water1", "water123")

        # Create an active order on Table 7
        with app.app_context():
            item = MenuItem.query.filter_by(available=True).first()
        self.client.post('/api/water/order', data=json.dumps({"table_number": 7, "cart": [{"id": item.id, "qty": 1}]}), content_type='application/json')

        res = self.client.get('/api/water/tables')
        self.assertEqual(res.status_code, 200)
        tables = res.get_json()
        self.assertIsInstance(tables, list)
        t7 = next((t for t in tables if t["number"] == 7), None)
        self.assertIsNotNone(t7)
        self.assertTrue(t7.get("has_active_order"))
        self.assertEqual(t7.get("status"), "occupied")
        self.assertIsNotNone(t7.get("active_order"))
        self.assertEqual(t7["active_order"]["item_count"], 1)

        self.logout()

    def test_water_order_timeline_api(self):
        """Water staff can view the chronological timeline of an order with additions."""
        self.login("water1", "water123")
        with app.app_context():
            item = MenuItem.query.filter_by(available=True).first()

        # Step 1: Create order
        res1 = self.client.post('/api/water/order', data=json.dumps({"table_number": 9, "cart": [{"id": item.id, "qty": 2}]}), content_type='application/json')
        order_id = res1.get_json()["order"]["id"]

        # Step 2: Add additional items
        self.client.post(f'/api/water/order/{order_id}/add-items', data=json.dumps({
            "cart": [{"open_item": True, "name": "Fresh Mineral Water Bottle", "price": 3.00, "qty": 1}]
        }), content_type='application/json')

        # Step 3: Fetch timeline
        res_tl = self.client.get(f'/api/water/order/{order_id}/timeline')
        self.assertEqual(res_tl.status_code, 200)
        data_tl = res_tl.get_json()
        self.assertTrue(data_tl.get("ok"))
        self.assertEqual(data_tl.get("table_number"), 9)
        events = data_tl.get("events", [])
        self.assertGreaterEqual(len(events), 2)
        # Event 1: Creation
        self.assertEqual(events[0]["event_type"], "created")
        # Event 2: Addition
        self.assertEqual(events[1]["event_type"], "add_items")
        self.assertIn("Fresh Mineral Water Bottle", events[1]["details"])

        self.logout()

    def test_water_active_and_my_orders_endpoints(self):
        """Water staff can view all active orders and their own order history."""
        self.login("water1", "water123")

        # Active orders endpoint
        res_active = self.client.get('/api/water/active-orders')
        self.assertEqual(res_active.status_code, 200)
        data_active = res_active.get_json()
        self.assertIsInstance(data_active, list)

        # My orders endpoint
        res_my = self.client.get('/api/water/my-orders')
        self.assertEqual(res_my.status_code, 200)
        data_my = res_my.get_json()
        self.assertIsInstance(data_my, list)

        self.logout()

    # ════════════════════════════════════════════════════════════
    # 7. ADMIN WATER MANAGEMENT (STAFF CRUD, PW RESET, AUDIT LOGS)
    # ════════════════════════════════════════════════════════════

    def test_admin_water_user_crud_and_logs(self):
        """Admin can list water users, create a new water user, toggle status, reset password, delete, and view logs."""
        self.login("admin", "admin123")

        # 1. Fetch water users
        res = self.client.get('/api/admin/water-users')
        self.assertEqual(res.status_code, 200)
        users = res.get_json()
        self.assertIsInstance(users, list)
        self.assertTrue(any(u["username"] == "water1" for u in users))

        # 2. Create new water user
        new_user_data = {
            "username": "water_test_99",
            "name": "Test Water Staff",
            "password": "pass99water",
            "permissions": {
                "can_create_order": True,
                "can_add_items": True,
                "can_open_item": False,
                "can_view_active_orders": True
            }
        }
        res_create = self.client.post('/api/admin/water-user', data=json.dumps(new_user_data), content_type='application/json')
        self.assertEqual(res_create.status_code, 200)
        user_id = res_create.get_json().get("id")
        self.assertIsNotNone(user_id)

        # Verify created user in DB
        with app.app_context():
            u = db.session.get(StaffUser, user_id)
            self.assertIsNotNone(u)
            self.assertEqual(u.role, "water")
            self.assertFalse(u.can_water_action("can_open_item"))
            self.assertTrue(u.can_water_action("can_add_items"))

        # 3. Toggle user active status
        res_toggle = self.client.post(f'/api/admin/water-user/{user_id}/toggle')
        self.assertEqual(res_toggle.status_code, 200)
        self.assertFalse(res_toggle.get_json().get("active"))

        # Toggle back active
        self.client.post(f'/api/admin/water-user/{user_id}/toggle')

        # 4. Reset password
        res_pw = self.client.post(f'/api/admin/water-user/{user_id}/reset-password', data=json.dumps({"password": "newsecret123"}), content_type='application/json')
        self.assertEqual(res_pw.status_code, 200)

        # 5. Verify login with new password
        self.logout()
        res_login_new = self.login("water_test_99", "newsecret123")
        self.assertEqual(res_login_new.status_code, 200)
        self.logout()

        # 6. Re-login as admin and delete user
        self.login("admin", "admin123")
        res_del = self.client.post(f'/api/admin/water-user/{user_id}/delete')
        self.assertEqual(res_del.status_code, 200)
        with app.app_context():
            self.assertIsNone(db.session.get(StaffUser, user_id))

        # 7. Check audit logs endpoint
        res_logs = self.client.get('/api/admin/water-logs')
        self.assertEqual(res_logs.status_code, 200)
        logs = res_logs.get_json()
        self.assertIsInstance(logs, list)

        self.logout()

    # ════════════════════════════════════════════════════════════
    # 9. MOBILE WEB, PWA MANIFEST, APK DOWNLOAD & APP CONFIG
    # ════════════════════════════════════════════════════════════

    def test_water_manifest_endpoint(self):
        """PWA manifest should return valid JSON with portrait standalone config and /water scope."""
        res = self.client.get('/water/manifest.json')
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertIn("name", data)
        self.assertEqual(data.get("start_url"), "/water")
        self.assertEqual(data.get("scope"), "/water")
        self.assertEqual(data.get("display"), "standalone")
        self.assertEqual(data.get("orientation"), "portrait")
        self.assertIn("icons", data)
        self.assertGreater(len(data["icons"]), 0)

    def test_water_download_portal_page(self):
        """Visiting /water/download should return the mobile app & APK download portal."""
        res = self.client.get('/water/download')
        self.assertEqual(res.status_code, 200)
        self.assertIn(b"Download Android APK", res.data)
        self.assertIn(b"Install Web App", res.data)
        self.assertIn(b"/api/water/download-apk", res.data)
        self.assertIn(b"/water", res.data)

    def test_water_apk_download_endpoint(self):
        """GET /api/water/download-apk should serve the standalone APK as an attachment."""
        res = self.client.get('/api/water/download-apk')
        self.assertEqual(res.status_code, 200)
        self.assertIn("application/vnd.android.package-archive", res.headers.get("Content-Type", ""))
        self.assertIn("attachment", res.headers.get("Content-Disposition", ""))
        self.assertTrue(res.data.startswith(b"PK\x03\x04"), "APK must be a valid zip archive starting with PK")
        self.assertGreater(len(res.data), 10000, "APK binary should have substantial size")

    def test_water_mobile_login_post_and_flow(self):
        """Test authentication via the dedicated mobile login screen."""
        # 1. Invalid credentials
        res_fail = self.client.post('/water/login', data={'username': 'water1', 'password': 'wrongpassword'})
        self.assertEqual(res_fail.status_code, 200)
        self.assertIn(b"Invalid username or password", res_fail.data)

        # 2. Valid credentials redirects to /water
        res_ok = self.client.post('/water/login', data={'username': 'water1', 'password': 'water123'}, follow_redirects=False)
        self.assertEqual(res_ok.status_code, 302)
        self.assertIn('/water', res_ok.headers.get('Location', ''))

        # 3. Following redirect loads water panel
        res_panel = self.client.get('/water')
        self.assertEqual(res_panel.status_code, 200)
        self.assertIn(b"Water Service Panel", res_panel.data)

        # 4. Visiting /water/login when already authenticated redirects to /water
        res_relogin = self.client.get('/water/login', follow_redirects=False)
        self.assertEqual(res_relogin.status_code, 302)
        self.assertIn('/water', res_relogin.headers.get('Location', ''))

        self.logout()

    def test_admin_water_app_config_get_and_post(self):
        """Admin can retrieve and update mobile app branding and configuration."""
        self.login("admin", "admin123")

        # GET config
        res = self.client.get('/api/admin/water-app-config')
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data.get("ok"))
        self.assertIn("config", data)
        self.assertIn("water_app_name", data["config"])
        self.assertIn("apk_download_url", data["config"])

        # POST updated config
        update_payload = {
            "water_app_name": "ISB Mobile Water",
            "water_app_short_name": "ISB Mobile",
            "water_app_version": "1.2.0",
            "water_apk_filename": "isb-water-v1.2.0.apk"
        }
        res_post = self.client.post(
            '/api/admin/water-app-config',
            data=json.dumps(update_payload),
            content_type='application/json'
        )
        self.assertEqual(res_post.status_code, 200)
        post_data = res_post.get_json()
        self.assertTrue(post_data.get("ok"))
        self.assertEqual(post_data["config"]["water_app_name"], "ISB Mobile Water")
        self.assertEqual(post_data["config"]["water_app_version"], "1.2.0")

        # Verify dynamic PWA manifest uses updated settings
        res_manifest = self.client.get('/water/manifest.json')
        manifest_data = res_manifest.get_json()
        self.assertEqual(manifest_data["name"], "ISB Mobile Water")
        self.assertEqual(manifest_data["short_name"], "ISB Mobile")

        self.logout()

if __name__ == "__main__":
    unittest.main()
