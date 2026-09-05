"""
Comprehensive E2E Test Suite for:
1. QR Logo Fix (ISB branding)
2. Thermal Receipt Printing (80mm, 58mm, A4, pitch-black crisp text, auto height)
3. 'Chace' System Suite:
   - Module A: Smart Cache Strategy (no-cache dynamic QRs, versioning)
   - Module B: Order Chase / Rush Kitchen System
   - Module C: Change Table System
   - Module D: Cash & Change Register System
"""
import os
import io
import uuid
import unittest
from PIL import Image
from app import app, db, seed, Order, RestaurantTable, StaffUser, Waiter, MenuItem

class TestLogoPrintAndChaceE2E(unittest.TestCase):
    def setUp(self):
        app.config["TESTING"] = True
        app.config["WTF_CSRF_ENABLED"] = False
        self.client = app.test_client()

        with app.app_context():
            db.create_all()
            seed()
            # Ensure tables 1-12 exist and default ranges are set
            t2 = RestaurantTable.query.filter_by(number=2).first()
            if t2:
                t2.assigned_waiter_name = "Ahmed"
            t8 = RestaurantTable.query.filter_by(number=8).first()
            if t8:
                t8.assigned_waiter_name = "Bilal"
            db.session.commit()

    def login(self, username, password):
        return self.client.post('/login', data={'username': username, 'password': password}, follow_redirects=True)

    # ════════════════════════════════════════════════════════════
    # 1. QR CODE LOGO FIX (ISB BRANDING)
    # ════════════════════════════════════════════════════════════

    def test_qr_generation_with_isb_emblem(self):
        """Table QR endpoint returns a valid PNG image with embedded ISB center logo."""
        res = self.client.get('/admin/qr/1.png')
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.mimetype, 'image/png')

        # Verify it is a valid, readable PNG image
        img = Image.open(io.BytesIO(res.data))
        self.assertEqual(img.format, 'PNG')
        self.assertGreaterEqual(img.width, 300)
        self.assertGreaterEqual(img.height, 300)

        # Verify static ISB emblem file exists and is valid
        emblem_path = os.path.join(app.root_path, 'static', 'isb_qr_emblem.png')
        self.assertTrue(os.path.exists(emblem_path))
        emblem_img = Image.open(emblem_path)
        self.assertEqual(emblem_img.format, 'PNG')

        # Verify favicon.jpg is the updated ISB branding
        fav_path = os.path.join(app.root_path, 'static', 'favicon.jpg')
        self.assertTrue(os.path.exists(fav_path))

    # ════════════════════════════════════════════════════════════
    # 2. THERMAL RECEIPT & INVOICE PRINTING
    # ════════════════════════════════════════════════════════════

    def test_thermal_bill_rendering_80mm(self):
        """Bill template renders 80mm thermal roll format with crisp black styling and change due."""
        with app.app_context():
            order = Order(
                order_no=f"PRINT-TEST-{uuid.uuid4().hex[:6]}",
                order_type="dine_in",
                table_number=3,
                customer_name="Walk-In",
                waiter_name="Ahmed",
                status="confirmed",
                payment_status="paid",
                payment_method="cash",
                total=45.00,
                subtotal=42.45,
                tax=2.55,
                customer_paid=50.00,
                change_due=5.00,
                source="customer_qr"
            )
            db.session.add(order)
            db.session.commit()
            oid = order.id

        self.login('admin', 'admin123')

        # 1. Default / thermal format
        res = self.client.get(f'/bill/{oid}')
        self.assertEqual(res.status_code, 200)
        html = res.data.decode('utf-8')
        
        # Verify 80mm thermal rules
        self.assertIn('80mm auto', html)
        self.assertIn('Islamabad Restaurant', html)
        self.assertIn('TABLE 3', html)
        self.assertIn('RM45.00', html)
        self.assertIn('Cash Tendered:', html)
        self.assertIn('RM50.00', html)
        self.assertIn('Change Due:', html)
        self.assertIn('RM5.00', html)
        self.assertIn('color: #000000 !important', html)

        # 2. A4 format
        res_a4 = self.client.get(f'/bill/{oid}?format=a4')
        self.assertEqual(res_a4.status_code, 200)
        html_a4 = res_a4.data.decode('utf-8')
        self.assertIn('size: A4 portrait', html_a4)

        # 3. 58mm format
        res_58 = self.client.get(f'/bill/{oid}?format=58mm')
        self.assertEqual(res_58.status_code, 200)
        html_58 = res_58.data.decode('utf-8')
        self.assertIn('size: 58mm auto', html_58)

    # ════════════════════════════════════════════════════════════
    # 3. 'CHACE' MODULE A — SMART CACHING
    # ════════════════════════════════════════════════════════════

    def test_cache_strategy_headers(self):
        """Dynamic QR codes have no-cache headers; static assets allow revalidation."""
        # Dynamic QR
        res_qr = self.client.get('/admin/qr/2.png')
        self.assertIn('no-cache', res_qr.headers.get('Cache-Control', ''))

        # Static assets
        res_static = self.client.get('/static/favicon.jpg')
        cc_static = res_static.headers.get('Cache-Control', '')
        self.assertNotIn('immutable', cc_static)

    # ════════════════════════════════════════════════════════════
    # 4. 'CHACE' MODULE B — ORDER CHASE / RUSH KITCHEN SYSTEM
    # ════════════════════════════════════════════════════════════

    def test_order_chase_api_and_kitchen_exposure(self):
        """Staff/customer can chase an order, which marks is_chased=True and exposes it to kitchen."""
        with app.app_context():
            order = Order(
                order_no=f"CHASE-{uuid.uuid4().hex[:6]}",
                order_type="dine_in",
                table_number=4,
                status="confirmed",
                payment_status="pay_at_counter",
                total=30.00
            )
            db.session.add(order)
            db.session.commit()
            oid = order.id

        # 1. Chase the order
        res = self.client.post(f'/api/order/{oid}/chase')
        self.assertEqual(res.status_code, 200)
        d = res.get_json()
        self.assertTrue(d['ok'])
        self.assertTrue(d['is_chased'])

        # 2. Verify in DB
        with app.app_context():
            updated = db.session.get(Order, oid)
            self.assertTrue(updated.is_chased)
            self.assertIsNotNone(updated.chased_at)

        # 3. Verify kitchen API returns is_chased=True
        self.login('admin', 'admin123')
        res_k = self.client.get('/api/kitchen/orders')
        self.assertEqual(res_k.status_code, 200)
        k_orders = res_k.get_json()
        matching = [o for o in k_orders if o['id'] == oid]
        self.assertTrue(len(matching) > 0)
        self.assertTrue(matching[0]['is_chased'])

    # ════════════════════════════════════════════════════════════
    # 5. 'CHACE' MODULE C — CHANGE TABLE SYSTEM
    # ════════════════════════════════════════════════════════════

    def test_order_change_table_updates_waiter_and_table_status(self):
        """Moving an order from Table 2 to Table 8 transfers assigned waiter and updates occupancy."""
        with app.app_context():
            # Complete any older active orders at Table 2 and Table 8
            for prev_o in Order.query.filter(Order.table_number.in_([2, 8])).all():
                prev_o.status = "completed"
            db.session.commit()

            order = Order(
                order_no=f"MOVE-{uuid.uuid4().hex[:6]}",
                order_type="dine_in",
                table_number=2,
                waiter_name="Ahmed",
                status="confirmed",
                total=55.00
            )
            t2 = RestaurantTable.query.filter_by(number=2).first()
            t8 = RestaurantTable.query.filter_by(number=8).first()
            t2.status = "occupied"
            t8.status = "free"
            db.session.add(order)
            db.session.commit()
            oid = order.id

        self.login('admin', 'admin123')

        # Transfer order from Table 2 to Table 8
        res = self.client.post(f'/api/order/{oid}/change-table', json={
            'new_table_number': 8
        })
        self.assertEqual(res.status_code, 200)
        d = res.get_json()
        self.assertTrue(d['ok'])
        self.assertEqual(d['new_table'], 8)
        self.assertEqual(d['waiter_name'], 'Bilal')

        # Verify database state
        with app.app_context():
            updated_order = db.session.get(Order, oid)
            self.assertEqual(updated_order.table_number, 8)
            self.assertEqual(updated_order.waiter_name, "Bilal")
            
            t2 = RestaurantTable.query.filter_by(number=2).first()
            t8 = RestaurantTable.query.filter_by(number=8).first()
            self.assertEqual(t8.status, "occupied")
            self.assertEqual(t2.status, "free")

    # ════════════════════════════════════════════════════════════
    # 6. 'CHACE' MODULE D — CASH & CHANGE REGISTER SYSTEM
    # ════════════════════════════════════════════════════════════

    def test_cash_register_tender_and_change_due(self):
        """Collecting cash payment calculates exact change due and marks order as paid."""
        with app.app_context():
            order = Order(
                order_no=f"REGISTER-{uuid.uuid4().hex[:6]}",
                order_type="dine_in",
                table_number=5,
                status="pending",
                payment_status="pay_at_counter",
                total=23.50,
                subtotal=22.17,
                tax=1.33
            )
            db.session.add(order)
            db.session.commit()
            oid = order.id

        self.login('staff1', 'staff123')

        res = self.client.post(f'/api/order/{oid}/collect-counter-payment', json={
            'payment_method': 'cash',
            'customer_paid': 50.00
        })
        self.assertEqual(res.status_code, 200)
        d = res.get_json()
        self.assertTrue(d['ok'])
        ord_data = d['order']
        self.assertEqual(ord_data['payment_status'], 'paid')
        self.assertEqual(ord_data['customer_paid'], 50.00)
        self.assertEqual(ord_data['change_due'], 26.50)

        # Verify receipt reflects this
        res_receipt = self.client.get(f'/bill/{oid}')
        html = res_receipt.data.decode('utf-8')
        self.assertIn('RM50.00', html)
        self.assertIn('RM26.50', html)
        self.assertIn('*** PAID ***', html)


if __name__ == '__main__':
    unittest.main()
