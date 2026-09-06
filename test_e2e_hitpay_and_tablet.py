"""
Comprehensive E2E Test Suite for HitPay Payment, Waiter/Manager Range Assignment,
and Staff Tablet Boundaries in Islamabad Restaurant & Cafe System.
"""
import os
import json
import uuid
import hmac
import hashlib
import unittest
from app import app, db, seed, Order, RestaurantTable, TableRequest, StaffUser, Waiter, MenuItem

class TestHitPayAndTabletE2E(unittest.TestCase):
    def setUp(self):
        app.config["TESTING"] = True
        app.config["WTF_CSRF_ENABLED"] = False
        app.config["HITPAY_SALT"] = "test_webhook_salt_xyz123"
        app.config["HITPAY_API_KEY"] = "test_api_key_abc"
        self.client = app.test_client()

        with app.app_context():
            db.create_all()
            seed()
            # Ensure tables 1-12 exist and default ranges are set
            t1 = RestaurantTable.query.filter_by(number=2).first()
            if t1:
                t1.assigned_waiter_name = "Ahmed"
            t8 = RestaurantTable.query.filter_by(number=8).first()
            if t8:
                t8.assigned_waiter_name = "Bilal"
            db.session.commit()

    def login(self, username, password):
        return self.client.post('/login', data={'username': username, 'password': password}, follow_redirects=True)

    # ════════════════════════════════════════════════════════════════════
    # 1. HITPAY PAYMENT & WEBHOOK SECURITY
    # ════════════════════════════════════════════════════════════════════

    def test_hitpay_webhook_valid_signature_marks_paid(self):
        """HitPay webhook marks order as paid only with valid HMAC-SHA256 signature."""
        order_num = f"HITPAY-TEST-{uuid.uuid4().hex[:6]}"
        with app.app_context():
            item = MenuItem.query.filter_by(available=True).first()
            order = Order(
                order_no=order_num,
                order_type="dine_in",
                table_number=2,
                status="pending",
                payment_method="hitpay",
                payment_status="unpaid",
                total=50.00,
                subtotal=47.17,
                tax=2.83,
                source="customer_qr",
                created_by="customer_qr",
                waiter_name="Ahmed"
            )
            db.session.add(order)
            db.session.commit()

        # Build webhook payload
        payload = {
            "status": "completed",
            "reference_number": order_num,
            "payment_id": "hp_pay_123456",
            "payment_type": "duitnow_qr",
            "amount": "50.00"
        }
        body_bytes = json.dumps(payload).encode('utf-8')
        salt = app.config["HITPAY_SALT"]
        valid_signature = hmac.new(salt.encode(), body_bytes, hashlib.sha256).hexdigest()

        # Send webhook with valid signature
        res = self.client.post(
            "/api/hitpay/webhook",
            data=body_bytes,
            content_type="application/json",
            headers={"Hitpay-Signature": valid_signature}
        )
        self.assertEqual(res.status_code, 200)

        with app.app_context():
            updated = Order.query.filter_by(order_no=order_num).first()
            self.assertEqual(updated.payment_status, "paid")
            self.assertEqual(updated.status, "confirmed")
            self.assertEqual(updated.payment_method, "duitnow_qr")
            self.assertEqual(updated.payment_ref, "hp_pay_123456")
            self.assertEqual(updated.customer_paid, 50.00)

    def test_hitpay_webhook_invalid_signature_rejected(self):
        """HitPay webhook rejects requests with invalid HMAC signature with 401."""
        payload = {
            "status": "completed",
            "reference_number": "FAKE-001",
            "amount": "100.00"
        }
        body_bytes = json.dumps(payload).encode('utf-8')

        res = self.client.post(
            "/api/hitpay/webhook",
            data=body_bytes,
            content_type="application/json",
            headers={"Hitpay-Signature": "invalid_forged_signature_123"}
        )
        self.assertEqual(res.status_code, 401)

    def test_hitpay_webhook_amount_mismatch_rejected(self):
        """HitPay webhook rejects requests if amount paid is less than order total."""
        order_num = f"HITPAY-SHORT-{uuid.uuid4().hex[:6]}"
        with app.app_context():
            order = Order(
                order_no=order_num,
                order_type="dine_in",
                table_number=5,
                status="pending",
                payment_method="hitpay",
                payment_status="unpaid",
                total=80.00,
                subtotal=75.47,
                tax=4.53
            )
            db.session.add(order)
            db.session.commit()

        payload = {
            "status": "completed",
            "reference_number": order_num,
            "amount": "10.00"  # Short by 70.00!
        }
        body_bytes = json.dumps(payload).encode('utf-8')
        salt = app.config["HITPAY_SALT"]
        valid_sig = hmac.new(salt.encode(), body_bytes, hashlib.sha256).hexdigest()

        res = self.client.post(
            "/api/hitpay/webhook",
            data=body_bytes,
            content_type="application/json",
            headers={"Hitpay-Signature": valid_sig}
        )
        self.assertEqual(res.status_code, 400)
        self.assertIn(b"Amount mismatch", res.data)

        with app.app_context():
            chk = Order.query.filter_by(order_no=order_num).first()
            self.assertEqual(chk.payment_status, "unpaid")

    def test_hitpay_webhook_idempotency(self):
        """Duplicate HitPay webhooks do not cause duplicate processing."""
        order_num = f"HITPAY-IDEM-{uuid.uuid4().hex[:6]}"
        with app.app_context():
            order = Order(
                order_no=order_num,
                order_type="dine_in",
                status="confirmed",
                payment_status="paid",
                payment_method="hitpay",
                total=30.00,
                customer_paid=30.00
            )
            db.session.add(order)
            db.session.commit()

        payload = {
            "status": "completed",
            "reference_number": order_num,
            "amount": "30.00",
            "payment_type": "hitpay"
        }
        body_bytes = json.dumps(payload).encode('utf-8')
        salt = app.config["HITPAY_SALT"]
        sig = hmac.new(salt.encode(), body_bytes, hashlib.sha256).hexdigest()

        res = self.client.post(
            "/api/hitpay/webhook",
            data=body_bytes,
            content_type="application/json",
            headers={"Hitpay-Signature": sig}
        )
        self.assertEqual(res.status_code, 200)

    # ════════════════════════════════════════════════════════════════════
    # 2. TABLE RANGE ASSIGNMENT & AUTO-ROUTING (AHMED & BILAL)
    # ════════════════════════════════════════════════════════════════════

    def test_admin_table_range_assignment(self):
        """Admin can assign a range of tables to a waiter (e.g. Tables 1-5 to Ahmed, 6-10 to Bilal)."""
        self.login('admin', 'admin123')

        # Assign 1-5 to Ahmed
        res1 = self.client.post('/api/admin/tables/assign-range', json={
            'waiter_name': 'Ahmed',
            'from_table': 1,
            'to_table': 5
        })
        self.assertEqual(res1.status_code, 200)
        d1 = res1.get_json()
        self.assertTrue(d1['ok'])
        self.assertEqual(d1['assigned_count'], 5)

        # Assign 6-10 to Bilal
        res2 = self.client.post('/api/admin/tables/assign-range', json={
            'waiter_name': 'Bilal',
            'from_table': 6,
            'to_table': 10
        })
        self.assertEqual(res2.status_code, 200)

        with app.app_context():
            t1 = RestaurantTable.query.filter_by(number=1).first()
            t5 = RestaurantTable.query.filter_by(number=5).first()
            t6 = RestaurantTable.query.filter_by(number=6).first()
            t10 = RestaurantTable.query.filter_by(number=10).first()
            self.assertEqual(t1.assigned_waiter_name, "Ahmed")
            self.assertEqual(t5.assigned_waiter_name, "Ahmed")
            self.assertEqual(t6.assigned_waiter_name, "Bilal")
            self.assertEqual(t10.assigned_waiter_name, "Bilal")

    def test_qr_order_auto_routes_to_assigned_waiter_and_pay_at_counter(self):
        """QR order from Table 2 auto-attaches to Ahmed with payment_status='pay_at_counter'."""
        with app.app_context():
            item = MenuItem.query.filter_by(available=True).first()
            t2 = RestaurantTable.query.filter_by(number=2).first()
            token = t2.token

        res = self.client.post('/api/checkout', json={
            'table_number': 2,
            'table_token': token,
            'payment_method': 'counter',
            'cart': [{'id': item.id, 'qty': 2, 'size': 'full'}]
        })
        self.assertEqual(res.status_code, 200)
        d = res.get_json()
        self.assertEqual(d['table_number'], 2)
        self.assertEqual(d['payment_status'], 'pay_at_counter')
        self.assertEqual(d['waiter_name'], 'Ahmed')

    def test_call_bell_auto_routes_to_assigned_waiter(self):
        """Customer call bell from Table 8 auto-attaches to Bilal."""
        with app.app_context():
            t8 = RestaurantTable.query.filter_by(number=8).first()
            token = t8.token

        res = self.client.post('/api/table/request', json={
            'table_number': 8,
            'table_token': token,
            'request_type': 'water',
            'message': 'Two glasses of cold water please'
        })
        self.assertEqual(res.status_code, 200)
        d = res.get_json()
        self.assertTrue(d['ok'])
        req = d['request']
        self.assertEqual(req['table_number'], 8)
        self.assertEqual(req['assigned_waiter_name'], 'Bilal')

    # ════════════════════════════════════════════════════════════════════
    # 3. MANAGER ROLE BOUNDARY & BACKEND RESTRICTION
    # ════════════════════════════════════════════════════════════════════

    def test_manager_role_boundary_restriction(self):
        """Manager can punch orders for any table, but MUST NOT see all restaurant orders."""
        # 1. Create a background customer QR order at Table 1
        other_order_no = f"CUST-QR-{uuid.uuid4().hex[:6]}"
        with app.app_context():
            item = MenuItem.query.filter_by(available=True).first()
            other_order = Order(
                order_no=other_order_no,
                order_type="dine_in",
                table_number=1,
                status="confirmed",
                payment_status="pay_at_counter",
                total=45.00,
                created_by="customer_qr",
                waiter_name="Ahmed"
            )
            db.session.add(other_order)
            db.session.commit()

        # 2. Login as Manager
        self.login('manager', 'manager123')

        # 3. Manager punches an order for Table 9 (Bilal's table) - allowed for manager!
        with app.app_context():
            item = MenuItem.query.filter_by(available=True).first()
            item_id = item.id

        punch_res = self.client.post('/api/staff/order/create', json={
            'table_number': 9,
            'cart': [{'id': item_id, 'qty': 1, 'size': 'full'}]
        })
        self.assertEqual(punch_res.status_code, 200)
        pdata = punch_res.get_json()
        self.assertTrue(pdata['ok'])
        self.assertEqual(pdata['order']['created_by'], 'manager')
        self.assertEqual(pdata['order']['source'], 'manager_tablet')

        # 4. Manager queries orders via /api/staff/orders and /api/pos/orders
        staff_orders_res = self.client.get('/api/staff/orders')
        self.assertEqual(staff_orders_res.status_code, 200)
        staff_orders = staff_orders_res.get_json()

        # Verify manager ONLY sees their own order, NOT the customer QR order for Ahmed
        order_nos = [o['order_no'] for o in staff_orders]
        self.assertIn(pdata['order']['order_no'], order_nos)
        self.assertNotIn(other_order_no, order_nos)

        # Also verify /api/pos/orders enforces manager restriction
        pos_orders_res = self.client.get('/api/pos/orders')
        self.assertEqual(pos_orders_res.status_code, 200)
        pos_order_nos = [o['order_no'] for o in pos_orders_res.get_json()]
        self.assertNotIn(other_order_no, pos_order_nos)

    # ════════════════════════════════════════════════════════════════════
    # 4. WAITER TABLET FILTERING (AHMED)
    # ════════════════════════════════════════════════════════════════════

    def test_waiter_tablet_calls_and_orders_filtering(self):
        """Waiter Ahmed only sees call bells from Tables 1-5, not Bilal's Tables 6-10."""
        with app.app_context():
            # Call for Ahmed's table (Table 3)
            req_ahmed = TableRequest(table_number=3, request_type="bill", status="pending", assigned_waiter_name="Ahmed")
            # Call for Bilal's table (Table 7)
            req_bilal = TableRequest(table_number=7, request_type="water", status="pending", assigned_waiter_name="Bilal")
            db.session.add(req_ahmed)
            db.session.add(req_bilal)
            db.session.commit()

        # Login as Ahmed
        self.login('ahmed', 'waiter123')

        calls_res = self.client.get('/api/staff/table-requests')
        self.assertEqual(calls_res.status_code, 200)
        calls = calls_res.get_json()
        table_nums = [c['table_number'] for c in calls]

        self.assertIn(3, table_nums)
        self.assertNotIn(7, table_nums)

    # ════════════════════════════════════════════════════════════════════
    # 5. POS COUNTER PAYMENT COLLECTION
    # ════════════════════════════════════════════════════════════════════

    def test_pos_counter_payment_collection(self):
        """POS cashier can collect payment for a 'pay_at_counter' order and mark it paid."""
        counter_order_no = f"COUNTER-PAY-{uuid.uuid4().hex[:6]}"
        with app.app_context():
            order = Order(
                order_no=counter_order_no,
                order_type="dine_in",
                table_number=4,
                status="pending",
                payment_method="counter",
                payment_status="pay_at_counter",
                total=35.50,
                subtotal=33.49,
                tax=2.01,
                source="customer_qr",
                waiter_name="Ahmed"
            )
            db.session.add(order)
            db.session.commit()
            oid = order.id

        # Login as cashier or admin
        self.login('admin', 'admin123')

        res = self.client.post(f'/api/order/{oid}/collect-counter-payment', json={
            'payment_method': 'cash',
            'customer_paid': 50.00
        })
        self.assertEqual(res.status_code, 200)
        d = res.get_json()
        self.assertTrue(d['ok'])
        ord_data = d['order']
        self.assertEqual(ord_data['payment_status'], 'paid')
        self.assertEqual(ord_data['payment_method'], 'cash')
        self.assertEqual(ord_data['customer_paid'], 50.00)
        self.assertEqual(ord_data['change_due'], 14.50)
        self.assertEqual(ord_data['status'], 'confirmed')


if __name__ == '__main__':
    unittest.main()

