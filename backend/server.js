const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const axios = require('axios');
require('dotenv').config();

const app = express();

// Middleware
app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));

// Database Connection (Neon PostgreSQL)
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: {
        rejectUnauthorized: false
    }
});

// Initialize Database Tables
async function initializeDatabase() {
    try {
        await pool.query(`
            CREATE TABLE IF NOT EXISTS products (
                id SERIAL PRIMARY KEY,
                title VARCHAR(255) NOT NULL,
                type VARCHAR(50) NOT NULL,
                price DECIMAL(10, 2) NOT NULL,
                description TEXT,
                quantity INTEGER DEFAULT 0,
                available BOOLEAN DEFAULT true,
                images TEXT[],
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);

        await pool.query(`
            CREATE TABLE IF NOT EXISTS orders (
                id SERIAL PRIMARY KEY,
                order_id VARCHAR(50) UNIQUE NOT NULL,
                customer_name VARCHAR(255) NOT NULL,
                email VARCHAR(255) NOT NULL,
                phone VARCHAR(20) NOT NULL,
                latitude DECIMAL(10, 8) NOT NULL,
                longitude DECIMAL(11, 8) NOT NULL,
                items JSONB NOT NULL,
                total_amount DECIMAL(10, 2) NOT NULL,
                payment_status VARCHAR(20) DEFAULT 'pending',
                transaction_id VARCHAR(100),
                status VARCHAR(20) DEFAULT 'pending',
                delivery_time VARCHAR(100),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);

        await pool.query(`
            CREATE TABLE IF NOT EXISTS payment_transactions (
                id SERIAL PRIMARY KEY,
                checkout_request_id VARCHAR(100) UNIQUE NOT NULL,
                merchant_request_id VARCHAR(100),
                phone VARCHAR(20) NOT NULL,
                amount DECIMAL(10, 2) NOT NULL,
                status VARCHAR(20) DEFAULT 'pending',
                mpesa_receipt_number VARCHAR(100),
                transaction_date TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);

        console.log('Database tables initialized successfully');
    } catch (error) {
        console.error('Database initialization error:', error);
    }
}

initializeDatabase();

// Middleware: Verify Admin Token
function verifyAdmin(req, res, next) {
    const token = req.headers.authorization?.split(' ')[1];
    
    if (!token) {
        return res.status(401).json({ success: false, message: 'No token provided' });
    }
    
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.adminEmail = decoded.email;
        next();
    } catch (error) {
        return res.status(401).json({ success: false, message: 'Invalid token' });
    }
}

// M-Pesa Configuration
const MPESA_CONFIG = {
    consumerKey: process.env.MPESA_CONSUMER_KEY || '47f4e6afa6c076cc4044ccf7747504525d6caf22',
    consumerSecret: process.env.MPESA_CONSUMER_SECRET || '47f4e6afa6c076cc4044ccf7747504525d6caf22',
    shortCode: process.env.MPESA_SHORTCODE || '174379',
    passkey: process.env.MPESA_PASSKEY || 'bfb279f9aa9bdbcf158e97dd71a467cd2e0c893059b10f78e6b72ada1ed2c919',
    callbackUrl: process.env.MPESA_CALLBACK_URL || 'https://your-backend-url.onrender.com/api/payments/callback'
};

// Get M-Pesa Access Token
async function getMpesaToken() {
    try {
        const auth = Buffer.from(`${MPESA_CONFIG.consumerKey}:${MPESA_CONFIG.consumerSecret}`).toString('base64');
        
        const response = await axios.get(
            'https://sandbox.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials',
            {
                headers: {
                    'Authorization': `Basic ${auth}`
                }
            }
        );
        
        return response.data.access_token;
    } catch (error) {
        console.error('M-Pesa token error:', error.response?.data || error.message);
        throw new Error('Failed to get M-Pesa token');
    }
}

// Generate M-Pesa Password
function generateMpesaPassword() {
    const timestamp = new Date().toISOString().replace(/[^0-9]/g, '').slice(0, -3);
    const password = Buffer.from(`${MPESA_CONFIG.shortCode}${MPESA_CONFIG.passkey}${timestamp}`).toString('base64');
    return { password, timestamp };
}

// ==================== PUBLIC ROUTES ====================

// Get All Products
app.get('/api/products', async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT * FROM products ORDER BY created_at DESC'
        );
        res.json(result.rows);
    } catch (error) {
        console.error('Get products error:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// Get Single Product
app.get('/api/products/:id', async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT * FROM products WHERE id = $1',
            [req.params.id]
        );
        
        if (result.rows.length === 0) {
            return res.status(404).json({ success: false, message: 'Product not found' });
        }
        
        res.json(result.rows[0]);
    } catch (error) {
        console.error('Get product error:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// Initiate M-Pesa Payment
app.post('/api/payments/initiate', async (req, res) => {
    try {
        const { phone, totalAmount, fullName, email, latitude, longitude, items } = req.body;
        
        // Clean phone number (remove spaces, +, etc.)
        const cleanPhone = phone.replace(/\D/g, '');
        const formattedPhone = cleanPhone.startsWith('254') ? cleanPhone : `254${cleanPhone.substring(1)}`;
        
        // Get M-Pesa token
        const token = await getMpesaToken();
        const { password, timestamp } = generateMpesaPassword();
        
        // STK Push request
        const stkPushData = {
            BusinessShortCode: MPESA_CONFIG.shortCode,
            Password: password,
            Timestamp: timestamp,
            TransactionType: 'CustomerPayBillOnline',
            Amount: Math.ceil(totalAmount),
            PartyA: formattedPhone,
            PartyB: MPESA_CONFIG.shortCode,
            PhoneNumber: formattedPhone,
            CallBackURL: MPESA_CONFIG.callbackUrl,
            AccountReference: 'KukuYetu',
            TransactionDesc: 'Poultry Purchase'
        };
        
        const response = await axios.post(
            'https://sandbox.safaricom.co.ke/mpesa/stkpush/v1/processrequest',
            stkPushData,
            {
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Content-Type': 'application/json'
                }
            }
        );
        
        // Store transaction
        await pool.query(
            `INSERT INTO payment_transactions 
            (checkout_request_id, merchant_request_id, phone, amount, status) 
            VALUES ($1, $2, $3, $4, $5)`,
            [
                response.data.CheckoutRequestID,
                response.data.MerchantRequestID,
                formattedPhone,
                totalAmount,
                'pending'
            ]
        );
        
        res.json({
            success: true,
            checkoutRequestID: response.data.CheckoutRequestID,
            merchantRequestID: response.data.MerchantRequestID,
            message: 'Payment initiated successfully'
        });
        
    } catch (error) {
        console.error('Payment initiation error:', error.response?.data || error.message);
        res.status(500).json({ 
            success: false, 
            message: 'Payment initiation failed',
            error: error.response?.data || error.message 
        });
    }
});

// Check Payment Status
app.get('/api/payments/status/:checkoutRequestID', async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT * FROM payment_transactions WHERE checkout_request_id = $1',
            [req.params.checkoutRequestID]
        );
        
        if (result.rows.length === 0) {
            return res.json({ status: 'not_found' });
        }
        
        const transaction = result.rows[0];
        res.json({
            status: transaction.status,
            transactionId: transaction.mpesa_receipt_number
        });
        
    } catch (error) {
        console.error('Payment status error:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// M-Pesa Callback
app.post('/api/payments/callback', async (req, res) => {
    try {
        console.log('M-Pesa Callback:', JSON.stringify(req.body, null, 2));
        
        const { Body } = req.body;
        const { stkCallback } = Body;
        
        const checkoutRequestID = stkCallback.CheckoutRequestID;
        const resultCode = stkCallback.ResultCode;
        
        if (resultCode === 0) {
            // Payment successful
            const callbackMetadata = stkCallback.CallbackMetadata.Item;
            const mpesaReceiptNumber = callbackMetadata.find(item => item.Name === 'MpesaReceiptNumber')?.Value;
            const transactionDate = callbackMetadata.find(item => item.Name === 'TransactionDate')?.Value;
            
            await pool.query(
                `UPDATE payment_transactions 
                SET status = $1, mpesa_receipt_number = $2, transaction_date = $3, updated_at = CURRENT_TIMESTAMP 
                WHERE checkout_request_id = $4`,
                ['completed', mpesaReceiptNumber, new Date(transactionDate), checkoutRequestID]
            );
        } else {
            // Payment failed
            await pool.query(
                `UPDATE payment_transactions 
                SET status = $1, updated_at = CURRENT_TIMESTAMP 
                WHERE checkout_request_id = $2`,
                ['failed', checkoutRequestID]
            );
        }
        
        res.json({ ResultCode: 0, ResultDesc: 'Success' });
        
    } catch (error) {
        console.error('Callback error:', error);
        res.json({ ResultCode: 1, ResultDesc: 'Failed' });
    }
});

// Create Order
app.post('/api/orders', async (req, res) => {
    try {
        const { fullName, email, phone, latitude, longitude, items, totalAmount, transactionId, paymentStatus } = req.body;
        
        // Generate order ID
        const orderId = `KY${Date.now()}`;
        
        const result = await pool.query(
            `INSERT INTO orders 
            (order_id, customer_name, email, phone, latitude, longitude, items, total_amount, payment_status, transaction_id, status) 
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) 
            RETURNING *`,
            [
                orderId,
                fullName,
                email,
                phone,
                latitude,
                longitude,
                JSON.stringify(items),
                totalAmount,
                paymentStatus,
                transactionId,
                'pending'
            ]
        );
        
        res.json({
            success: true,
            orderId: orderId,
            ...result.rows[0],
            items: JSON.parse(result.rows[0].items)
        });
        
    } catch (error) {
        console.error('Create order error:', error);
        res.status(500).json({ success: false, message: 'Failed to create order' });
    }
});

// Get Order Status (for customer notifications)
app.get('/api/orders/:orderId/status', async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT * FROM orders WHERE order_id = $1',
            [req.params.orderId]
        );
        
        if (result.rows.length === 0) {
            return res.status(404).json({ success: false, message: 'Order not found' });
        }
        
        const order = result.rows[0];
        res.json({
            status: order.status,
            deliveryTime: order.delivery_time
        });
        
    } catch (error) {
        console.error('Get order status error:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// ==================== ADMIN ROUTES ====================

// Admin Login
app.post('/api/admin/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        
        // Check against environment variables
        if (email === process.env.ADMIN_EMAIL && password === process.env.ADMIN_PASSWORD) {
            const token = jwt.sign(
                { email: email },
                process.env.JWT_SECRET,
                { expiresIn: '24h' }
            );
            
            res.json({ success: true, token });
        } else {
            res.status(401).json({ success: false, message: 'Invalid credentials' });
        }
        
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// Get Dashboard Stats
app.get('/api/admin/stats', verifyAdmin, async (req, res) => {
    try {
        const ordersResult = await pool.query('SELECT COUNT(*) as count FROM orders');
        const pendingResult = await pool.query("SELECT COUNT(*) as count FROM orders WHERE status = 'pending'");
        const productsResult = await pool.query('SELECT COUNT(*) as count FROM products');
        const revenueResult = await pool.query("SELECT SUM(total_amount) as total FROM orders WHERE payment_status = 'paid'");
        
        res.json({
            totalOrders: parseInt(ordersResult.rows[0].count),
            pendingOrders: parseInt(pendingResult.rows[0].count),
            totalProducts: parseInt(productsResult.rows[0].count),
            totalRevenue: parseFloat(revenueResult.rows[0].total || 0)
        });
        
    } catch (error) {
        console.error('Stats error:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// Get Recent Orders
app.get('/api/admin/orders/recent', verifyAdmin, async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT * FROM orders ORDER BY created_at DESC LIMIT 10'
        );
        
        const orders = result.rows.map(order => ({
            ...order,
            items: JSON.parse(order.items)
        }));
        
        res.json(orders);
        
    } catch (error) {
        console.error('Recent orders error:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// Get All Orders
app.get('/api/admin/orders', verifyAdmin, async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT * FROM orders ORDER BY created_at DESC'
        );
        
        const orders = result.rows.map(order => ({
            _id: order.id,
            orderId: order.order_id,
            customerName: order.customer_name,
            email: order.email,
            phone: order.phone,
            location: {
                latitude: parseFloat(order.latitude),
                longitude: parseFloat(order.longitude)
            },
            items: JSON.parse(order.items),
            totalAmount: parseFloat(order.total_amount),
            paymentStatus: order.payment_status,
            status: order.status,
            deliveryTime: order.delivery_time,
            createdAt: order.created_at
        }));
        
        res.json(orders);
        
    } catch (error) {
        console.error('Get orders error:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// Confirm Order
app.post('/api/admin/orders/:id/confirm', verifyAdmin, async (req, res) => {
    try {
        const { deliveryTime } = req.body;
        
        await pool.query(
            `UPDATE orders 
            SET status = $1, delivery_time = $2, updated_at = CURRENT_TIMESTAMP 
            WHERE id = $3`,
            ['confirmed', deliveryTime, req.params.id]
        );
        
        res.json({ success: true, message: 'Order confirmed' });
        
    } catch (error) {
        console.error('Confirm order error:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// Add Product
app.post('/api/admin/products', verifyAdmin, async (req, res) => {
    try {
        const { title, type, price, description, quantity, available, images } = req.body;
        
        const result = await pool.query(
            `INSERT INTO products 
            (title, type, price, description, quantity, available, images) 
            VALUES ($1, $2, $3, $4, $5, $6, $7) 
            RETURNING *`,
            [title, type, price, description, quantity, available, images]
        );
        
        res.json({ success: true, product: result.rows[0] });
        
    } catch (error) {
        console.error('Add product error:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// Update Product
app.put('/api/admin/products/:id', verifyAdmin, async (req, res) => {
    try {
        const { title, type, price, description, quantity, available, images } = req.body;
        
        const result = await pool.query(
            `UPDATE products 
            SET title = $1, type = $2, price = $3, description = $4, quantity = $5, available = $6, images = $7, updated_at = CURRENT_TIMESTAMP 
            WHERE id = $8 
            RETURNING *`,
            [title, type, price, description, quantity, available, images, req.params.id]
        );
        
        res.json({ success: true, product: result.rows[0] });
        
    } catch (error) {
        console.error('Update product error:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// Delete Product
app.delete('/api/admin/products/:id', verifyAdmin, async (req, res) => {
    try {
        await pool.query('DELETE FROM products WHERE id = $1', [req.params.id]);
        res.json({ success: true, message: 'Product deleted' });
    } catch (error) {
        console.error('Delete product error:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// Health Check
app.get('/health', (req, res) => {
    res.json({ status: 'OK', timestamp: new Date().toISOString() });
});

// Start Server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});