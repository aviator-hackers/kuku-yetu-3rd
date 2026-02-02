const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const axios = require('axios');
require('dotenv').config();

const app = express();

// Middleware
app.use(cors({
    origin: ['https://kuku-yetu.netlify.app', 'http://localhost:3000', 'http://localhost:5500', 'http://127.0.0.1:5500'],
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));

// Handle pre-flight requests
app.options('*', (req, res) => {
    res.header('Access-Control-Allow-Origin', req.headers.origin || '*');
    res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    res.header('Access-Control-Allow-Credentials', 'true');
    res.status(200).send();
});

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
    const authHeader = req.headers.authorization;
    
    if (!authHeader) {
        return res.status(401).json({ success: false, message: 'No token provided' });
    }
    
    const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : authHeader;
    
    if (!token) {
        return res.status(401).json({ success: false, message: 'Invalid token format' });
    }
    
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key');
        req.adminEmail = decoded.email;
        next();
    } catch (error) {
        console.error('Token verification error:', error);
        return res.status(401).json({ success: false, message: 'Invalid token' });
    }
}

// M-Pesa Configuration
const MPESA_CONFIG = {
    consumerKey: process.env.MPESA_CONSUMER_KEY || '47f4e6afa6c076cc4044ccf7747504525d6caf22',
    consumerSecret: process.env.MPESA_CONSUMER_SECRET || '47f4e6afa6c076cc4044ccf7747504525d6caf22',
    shortCode: process.env.MPESA_SHORTCODE || '174379',
    passkey: process.env.MPESA_PASSKEY || 'bfb279f9aa9bdbcf158e97dd71a467cd2e0c893059b10f78e6b72ada1ed2c919',
    callbackUrl: process.env.MPESA_CALLBACK_URL || 'https://kuku-yetu-3rd.onrender.com/api/payments/callback'
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

// Get All Products - Returns array directly
app.get('/api/products', async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT *, id as _id FROM products WHERE available = true ORDER BY created_at DESC'
        );
        
        const products = result.rows.map(product => ({
            ...product,
            _id: product._id || product.id,
            images: product.images || ['https://images.unsplash.com/photo-1562967916-eb82221dfb92?ixlib=rb-1.2.1&auto=format&fit=crop&w=600&q=80']
        }));
        
        res.json(products); // Returns array directly
    } catch (error) {
        console.error('Get products error:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// Get Single Product
app.get('/api/products/:id', async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT *, id as _id FROM products WHERE id = $1',
            [req.params.id]
        );
        
        if (result.rows.length === 0) {
            return res.status(404).json({ success: false, message: 'Product not found' });
        }
        
        const product = result.rows[0];
        // Ensure images array exists
        if (!product.images || product.images.length === 0) {
            product.images = ['https://images.unsplash.com/photo-1562967916-eb82221dfb92?ixlib=rb-1.2.1&auto=format&fit=crop&w=600&q=80'];
        }
        
        res.json(product);
    } catch (error) {
        console.error('Get product error:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// Initiate M-Pesa Payment (with demo mode)
app.post('/api/payments/initiate', async (req, res) => {
    try {
        const { phone, totalAmount, fullName, email, latitude, longitude, items } = req.body;
        
        // Demo mode - simulate successful payment for testing
        const mockCheckoutRequestID = `DEMO-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
        const mockMerchantRequestID = `DEMO-MERCHANT-${Date.now()}`;
        
        // Store demo transaction
        await pool.query(
            `INSERT INTO payment_transactions 
            (checkout_request_id, merchant_request_id, phone, amount, status) 
            VALUES ($1, $2, $3, $4, $5)`,
            [
                mockCheckoutRequestID,
                mockMerchantRequestID,
                phone,
                totalAmount,
                'pending'
            ]
        );
        
        // Simulate immediate success for demo
        setTimeout(async () => {
            await pool.query(
                `UPDATE payment_transactions 
                SET status = $1, mpesa_receipt_number = $2, transaction_date = CURRENT_TIMESTAMP 
                WHERE checkout_request_id = $3`,
                ['completed', `MPESA${Date.now()}`, mockCheckoutRequestID]
            );
        }, 1000);
        
        res.json({
            success: true,
            checkoutRequestID: mockCheckoutRequestID,
            merchantRequestID: mockMerchantRequestID,
            message: 'Demo payment initiated successfully'
        });
        
    } catch (error) {
        console.error('Payment initiation error:', error.response?.data || error.message);
        res.status(500).json({ 
            success: false, 
            message: 'Payment initiation failed',
            error: error.message 
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
        
        // Demo mode: simulate success after 5 seconds
        if (transaction.checkout_request_id.startsWith('DEMO-')) {
            const createdAt = new Date(transaction.created_at);
            const now = new Date();
            const diffSeconds = (now - createdAt) / 1000;
            
            if (diffSeconds > 5 && transaction.status === 'pending') {
                // Update to completed
                await pool.query(
                    `UPDATE payment_transactions 
                    SET status = $1, mpesa_receipt_number = $2, transaction_date = CURRENT_TIMESTAMP 
                    WHERE checkout_request_id = $3`,
                    ['completed', `MPESA${Date.now()}`, req.params.checkoutRequestID]
                );
                
                return res.json({
                    status: 'completed',
                    transactionId: `MPESA${Date.now()}`
                });
            }
        }
        
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
        console.log('M-Pesa Callback received');
        
        const { Body } = req.body;
        const { stkCallback } = Body;
        
        const checkoutRequestID = stkCallback.CheckoutRequestID;
        const resultCode = stkCallback.ResultCode;
        
        if (resultCode === 0) {
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
        const orderId = `KY${Date.now()}${Math.floor(Math.random() * 1000)}`;
        
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
                latitude || 0,
                longitude || 0,
                JSON.stringify(items),
                totalAmount,
                paymentStatus || 'pending',
                transactionId,
                'pending'
            ]
        );
        
        res.json({
            success: true,
            orderId: orderId,
            order: result.rows[0],
            items: JSON.parse(result.rows[0].items)
        });
        
    } catch (error) {
        console.error('Create order error:', error);
        res.status(500).json({ success: false, message: 'Failed to create order' });
    }
});

// Get Order Status
app.get('/api/orders/:orderId/status', async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT status, delivery_time FROM orders WHERE order_id = $1',
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

// Admin Login - SIMPLE AND WORKING
app.post('/api/admin/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        
        console.log('Login attempt with:', email);
        
        // Simple check against environment variables
        const adminEmail = process.env.ADMIN_EMAIL || 'admin@kukuyetu.com';
        const adminPassword = process.env.ADMIN_PASSWORD || 'YourSecurePassword123!';
        
        if (email === adminEmail && password === adminPassword) {
            const token = jwt.sign(
                { email: email },
                process.env.JWT_SECRET || 'your-secret-key',
                { expiresIn: '24h' }
            );
            
            res.json({ 
                success: true, 
                token,
                user: { email: email }
            });
        } else {
            console.log('Login failed: Invalid credentials');
            res.status(401).json({ 
                success: false, 
                message: 'Invalid email or password' 
            });
        }
        
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Server error during login' 
        });
    }
});

// Get Dashboard Stats - Returns object with stats
app.get('/api/admin/stats', verifyAdmin, async (req, res) => {
    try {
        const ordersResult = await pool.query('SELECT COUNT(*) as count FROM orders');
        const pendingResult = await pool.query("SELECT COUNT(*) as count FROM orders WHERE status = 'pending'");
        const productsResult = await pool.query('SELECT COUNT(*) as count FROM products');
        const revenueResult = await pool.query("SELECT SUM(total_amount) as total FROM orders WHERE payment_status = 'paid'");
        
        res.json({
            success: true,
            totalOrders: parseInt(ordersResult.rows[0].count) || 0,
            pendingOrders: parseInt(pendingResult.rows[0].count) || 0,
            totalProducts: parseInt(productsResult.rows[0].count) || 0,
            totalRevenue: parseFloat(revenueResult.rows[0].total) || 0
        });
        
    } catch (error) {
        console.error('Stats error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Server error',
            error: error.message 
        });
    }
});

// Get Recent Orders - Returns array directly
app.get('/api/admin/orders/recent', verifyAdmin, async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT *, id as _id FROM orders 
            ORDER BY created_at DESC LIMIT 10`
        );
        
        const orders = result.rows.map(order => ({
            _id: order._id || order.id,
            orderId: order.order_id,
            customerName: order.customer_name,
            email: order.email,
            phone: order.phone,
            items: JSON.parse(order.items),
            totalAmount: parseFloat(order.total_amount),
            paymentStatus: order.payment_status,
            status: order.status,
            deliveryTime: order.delivery_time,
            createdAt: order.created_at
        }));
        
        res.json(orders); // Returns array directly
        
    } catch (error) {
        console.error('Recent orders error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Server error',
            error: error.message 
        });
    }
});

// Get All Orders - Returns array directly
app.get('/api/admin/orders', verifyAdmin, async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT *, id as _id FROM orders ORDER BY created_at DESC'
        );
        
        const orders = result.rows.map(order => ({
            _id: order._id || order.id,
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
        
        res.json(orders); // Returns array directly
        
    } catch (error) {
        console.error('Get orders error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Server error',
            error: error.message 
        });
    }
});

// Get Products for Admin - Returns array directly
app.get('/api/admin/products', verifyAdmin, async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT *, id as _id FROM products ORDER BY created_at DESC'
        );
        
        const products = result.rows.map(product => ({
            ...product,
            _id: product._id || product.id,
            price: parseFloat(product.price),
            quantity: parseInt(product.quantity),
            available: product.available !== false,
            images: product.images || ['https://images.unsplash.com/photo-1562967916-eb82221dfb92?ixlib=rb-1.2.1&auto=format&fit=crop&w=600&q=80']
        }));
        
        res.json(products); // Returns array directly
        
    } catch (error) {
        console.error('Get admin products error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Server error',
            error: error.message 
        });
    }
});

// Confirm Order
app.post('/api/admin/orders/:id/confirm', verifyAdmin, async (req, res) => {
    try {
        const { deliveryTime } = req.body;
        const orderId = req.params.id;
        
        if (!deliveryTime) {
            return res.status(400).json({ 
                success: false, 
                message: 'Delivery time is required' 
            });
        }
        
        await pool.query(
            `UPDATE orders 
            SET status = 'confirmed', delivery_time = $1, updated_at = CURRENT_TIMESTAMP 
            WHERE id = $2 OR order_id = $2`,
            [deliveryTime, orderId]
        );
        
        res.json({ 
            success: true, 
            message: 'Order confirmed successfully' 
        });
        
    } catch (error) {
        console.error('Confirm order error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Failed to confirm order',
            error: error.message 
        });
    }
});

// Add Product
app.post('/api/admin/products', verifyAdmin, async (req, res) => {
    try {
        const { title, type, price, description, quantity, available, images } = req.body;
        
        // Validate required fields
        if (!title || !type || !price) {
            return res.status(400).json({ 
                success: false, 
                message: 'Missing required fields' 
            });
        }
        
        const finalImages = images && images.length > 0 ? images : ['https://images.unsplash.com/photo-1562967916-eb82221dfb92?ixlib=rb-1.2.1&auto=format&fit=crop&w=600&q=80'];
        
        const result = await pool.query(
            `INSERT INTO products 
            (title, type, price, description, quantity, available, images) 
            VALUES ($1, $2, $3, $4, $5, $6, $7) 
            RETURNING *, id as _id`,
            [
                title, 
                type, 
                parseFloat(price), 
                description || '', 
                parseInt(quantity) || 0, 
                available !== false, 
                finalImages
            ]
        );
        
        res.json({ 
            success: true, 
            product: result.rows[0],
            message: 'Product added successfully'
        });
        
    } catch (error) {
        console.error('Add product error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Failed to add product',
            error: error.message 
        });
    }
});

// Update Product
app.put('/api/admin/products/:id', verifyAdmin, async (req, res) => {
    try {
        const { title, type, price, description, quantity, available, images } = req.body;
        
        const result = await pool.query(
            `UPDATE products 
            SET title = $1, type = $2, price = $3, description = $4, 
                quantity = $5, available = $6, images = $7, updated_at = CURRENT_TIMESTAMP 
            WHERE id = $8 
            RETURNING *, id as _id`,
            [
                title, 
                type, 
                parseFloat(price), 
                description, 
                parseInt(quantity) || 0, 
                available !== false, 
                images, 
                req.params.id
            ]
        );
        
        res.json({ 
            success: true, 
            product: result.rows[0],
            message: 'Product updated successfully'
        });
        
    } catch (error) {
        console.error('Update product error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Failed to update product',
            error: error.message 
        });
    }
});

// Delete Product
app.delete('/api/admin/products/:id', verifyAdmin, async (req, res) => {
    try {
        const productId = req.params.id;
        
        // Validate product ID
        if (!productId || isNaN(parseInt(productId))) {
            return res.status(400).json({ 
                success: false, 
                message: 'Invalid product ID' 
            });
        }
        
        await pool.query('DELETE FROM products WHERE id = $1', [productId]);
        
        res.json({ 
            success: true, 
            message: 'Product deleted successfully' 
        });
        
    } catch (error) {
        console.error('Delete product error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Failed to delete product',
            error: error.message 
        });
    }
});

// ==================== UTILITY ROUTES ====================

// Debug endpoint to test CORS
app.get('/api/test-cors', (req, res) => {
    res.json({
        success: true,
        message: 'CORS is working!',
        timestamp: new Date().toISOString(),
        origin: req.headers.origin
    });
});

// Debug endpoint for admin
app.get('/api/admin/test', verifyAdmin, (req, res) => {
    res.json({
        success: true,
        message: 'Admin API is working!',
        adminEmail: req.adminEmail,
        timestamp: new Date().toISOString()
    });
});

// Health Check
app.get('/health', async (req, res) => {
    try {
        await pool.query('SELECT 1');
        res.json({ 
            status: 'OK', 
            timestamp: new Date().toISOString(),
            database: 'connected'
        });
    } catch (error) {
        res.status(500).json({ 
            status: 'ERROR', 
            timestamp: new Date().toISOString(),
            database: 'disconnected',
            error: error.message
        });
    }
});

// API Documentation
app.get('/', (req, res) => {
    res.json({
        success: true,
        message: 'Kuku Yetu API Server',
        version: '1.0.0',
        status: 'running',
        timestamp: new Date().toISOString(),
        endpoints: {
            public: {
                products: {
                    getAll: 'GET /api/products',
                    getSingle: 'GET /api/products/:id'
                },
                orders: {
                    create: 'POST /api/orders',
                    status: 'GET /api/orders/:orderId/status'
                },
                payments: {
                    initiate: 'POST /api/payments/initiate',
                    status: 'GET /api/payments/status/:checkoutRequestID'
                }
            },
            admin: {
                auth: {
                    login: 'POST /api/admin/login'
                },
                dashboard: {
                    stats: 'GET /api/admin/stats',
                    recentOrders: 'GET /api/admin/orders/recent'
                },
                products: {
                    getAll: 'GET /api/admin/products',
                    create: 'POST /api/admin/products',
                    update: 'PUT /api/admin/products/:id',
                    delete: 'DELETE /api/admin/products/:id'
                },
                orders: {
                    getAll: 'GET /api/admin/orders',
                    confirm: 'POST /api/admin/orders/:id/confirm'
                }
            },
            utility: {
                health: 'GET /health',
                testCors: 'GET /api/test-cors',
                adminTest: 'GET /api/admin/test'
            }
        }
    });
});

// 404 handler for undefined routes
app.use((req, res) => {
    res.status(404).json({
        success: false,
        message: `Route not found: ${req.method} ${req.originalUrl}`
    });
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.error('Server error:', err);
    
    res.status(500).json({
        success: false,
        message: 'Internal server error',
        error: err.message,
        timestamp: new Date().toISOString()
    });
});

// Start Server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
    console.log(`🌐 CORS configured for:`);
    console.log(`   - https://kuku-yetu.netlify.app`);
    console.log(`   - http://localhost:3000`);
    console.log(`   - http://localhost:5500`);
    console.log(`📊 Health check: http://localhost:${PORT}/health`);
});
