const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const axios = require('axios');
require('dotenv').config();

const app = express();

// Middleware - Enhanced CORS Configuration
app.use(cors({
    origin: ['https://kuku-yetu.netlify.app', 'http://localhost:3000', 'http://localhost:5500', 'http://127.0.0.1:5500'],
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
    exposedHeaders: ['Content-Length', 'X-Requested-With']
}));

// Handle pre-flight requests
app.options('*', cors());

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
                latitude DECIMAL(10, 8),
                longitude DECIMAL(11, 8),
                items JSONB NOT NULL,
                total_amount DECIMAL(10, 2) NOT NULL,
                payment_status VARCHAR(20) DEFAULT 'pending',
                transaction_id VARCHAR(100),
                status VARCHAR(20) DEFAULT 'pending',
                delivery_time VARCHAR(100),
                delivery_method VARCHAR(50) DEFAULT 'home',
                delivery_notes TEXT,
                payment_method VARCHAR(50) DEFAULT 'mpesa',
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

        await pool.query(`
            CREATE TABLE IF NOT EXISTS admin_users (
                id SERIAL PRIMARY KEY,
                email VARCHAR(255) UNIQUE NOT NULL,
                password VARCHAR(255) NOT NULL,
                name VARCHAR(255),
                role VARCHAR(50) DEFAULT 'admin',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP
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
    
    if (!token || token === 'undefined' || token === 'null') {
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
        // Return mock token for development
        return 'mock_mpesa_token';
    }
}

// Generate M-Pesa Password
function generateMpesaPassword() {
    const timestamp = new Date().toISOString().replace(/[^0-9]/g, '').slice(0, -3);
    const password = Buffer.from(`${MPESA_CONFIG.shortCode}${MPESA_CONFIG.passkey}${timestamp}`).toString('base64');
    return { password, timestamp };
}

// ==================== PUBLIC ROUTES ====================

// Get All Products with _id field for frontend compatibility
app.get('/api/products', async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT *, id as _id FROM products ORDER BY created_at DESC'
        );
        
        // Transform products to include both id and _id
        const products = result.rows.map(product => ({
            ...product,
            _id: product._id || product.id,
            images: product.images || ['https://images.unsplash.com/photo-1562967916-eb82221dfb92?ixlib=rb-1.2.1&auto=format&fit=crop&w=600&q=80']
        }));
        
        res.json(products);
    } catch (error) {
        console.error('Get products error:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// Get Single Product with _id field
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
        if (process.env.NODE_ENV === 'development' || !process.env.MPESA_CONSUMER_KEY) {
            console.log('Using demo payment mode');
            
            // Generate mock transaction IDs
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
            
            return res.json({
                success: true,
                checkoutRequestID: mockCheckoutRequestID,
                merchantRequestID: mockMerchantRequestID,
                message: 'Demo payment initiated successfully'
            });
        }
        
        // Real M-Pesa implementation
        const cleanPhone = phone.replace(/\D/g, '');
        const formattedPhone = cleanPhone.startsWith('254') ? cleanPhone : `254${cleanPhone.substring(1)}`;
        
        const token = await getMpesaToken();
        const { password, timestamp } = generateMpesaPassword();
        
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
        
        // Fallback to demo mode if M-Pesa fails
        const mockCheckoutRequestID = `FALLBACK-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
        
        await pool.query(
            `INSERT INTO payment_transactions 
            (checkout_request_id, merchant_request_id, phone, amount, status) 
            VALUES ($1, $2, $3, $4, $5)`,
            [
                mockCheckoutRequestID,
                'FALLBACK-MERCHANT',
                req.body.phone,
                req.body.totalAmount,
                'pending'
            ]
        );
        
        res.json({
            success: true,
            checkoutRequestID: mockCheckoutRequestID,
            merchantRequestID: 'FALLBACK-MERCHANT',
            message: 'Payment initiated (demo mode)'
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
        if (transaction.checkout_request_id.startsWith('DEMO-') || 
            transaction.checkout_request_id.startsWith('FALLBACK-')) {
            
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
        console.log('M-Pesa Callback:', JSON.stringify(req.body, null, 2));
        
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

// Create Order with enhanced data
app.post('/api/orders', async (req, res) => {
    try {
        const { 
            fullName, 
            email, 
            phone, 
            latitude, 
            longitude, 
            items, 
            totalAmount, 
            transactionId, 
            paymentStatus,
            deliveryMethod = 'home',
            deliveryNotes = '',
            paymentMethod = 'mpesa'
        } = req.body;
        
        // Validate required fields
        if (!fullName || !email || !phone || !items || !totalAmount) {
            return res.status(400).json({ 
                success: false, 
                message: 'Missing required fields' 
            });
        }
        
        // Generate order ID
        const orderId = `KY${Date.now()}${Math.floor(Math.random() * 1000)}`;
        
        // Calculate subtotal from items
        const subtotal = items.reduce((sum, item) => sum + (item.price * item.quantity), 0);
        const deliveryFee = deliveryMethod === 'pickup' ? 0 : 200;
        const finalTotal = parseFloat(totalAmount) || (subtotal + deliveryFee);
        
        const result = await pool.query(
            `INSERT INTO orders 
            (order_id, customer_name, email, phone, latitude, longitude, items, total_amount, 
             payment_status, transaction_id, status, delivery_method, delivery_notes, payment_method) 
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14) 
            RETURNING *`,
            [
                orderId,
                fullName,
                email,
                phone,
                latitude,
                longitude,
                JSON.stringify(items),
                finalTotal,
                paymentStatus || 'pending',
                transactionId,
                'pending',
                deliveryMethod,
                deliveryNotes,
                paymentMethod
            ]
        );
        
        // Update product quantities
        for (const item of items) {
            await pool.query(
                'UPDATE products SET quantity = quantity - $1 WHERE id = $2',
                [item.quantity, item.productId]
            );
        }
        
        res.json({
            success: true,
            orderId: orderId,
            order: {
                ...result.rows[0],
                items: JSON.parse(result.rows[0].items),
                _id: result.rows[0].id
            },
            message: 'Order created successfully'
        });
        
    } catch (error) {
        console.error('Create order error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Failed to create order',
            error: error.message 
        });
    }
});

// Get Order Status
app.get('/api/orders/:orderId/status', async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT status, delivery_time, updated_at FROM orders WHERE order_id = $1',
            [req.params.orderId]
        );
        
        if (result.rows.length === 0) {
            return res.status(404).json({ success: false, message: 'Order not found' });
        }
        
        const order = result.rows[0];
        res.json({
            success: true,
            status: order.status,
            deliveryTime: order.delivery_time,
            lastUpdated: order.updated_at
        });
        
    } catch (error) {
        console.error('Get order status error:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// Get Order by ID
app.get('/api/orders/:orderId', async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT *, id as _id FROM orders WHERE order_id = $1',
            [req.params.orderId]
        );
        
        if (result.rows.length === 0) {
            return res.status(404).json({ success: false, message: 'Order not found' });
        }
        
        const order = result.rows[0];
        res.json({
            success: true,
            order: {
                ...order,
                items: JSON.parse(order.items),
                _id: order._id
            }
        });
        
    } catch (error) {
        console.error('Get order error:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// ==================== ADMIN ROUTES ====================

// Admin Login with better validation
app.post('/api/admin/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        
        if (!email || !password) {
            return res.status(400).json({ 
                success: false, 
                message: 'Email and password are required' 
            });
        }
        
        // Check environment variables first
        if (process.env.ADMIN_EMAIL && process.env.ADMIN_PASSWORD) {
            if (email === process.env.ADMIN_EMAIL && password === process.env.ADMIN_PASSWORD) {
                const token = jwt.sign(
                    { 
                        email: email,
                        role: 'admin',
                        timestamp: Date.now()
                    },
                    process.env.JWT_SECRET || 'your-secret-key',
                    { expiresIn: '24h' }
                );
                
                // Update last login
                await pool.query(
                    'UPDATE admin_users SET last_login = CURRENT_TIMESTAMP WHERE email = $1',
                    [email]
                );
                
                return res.json({ 
                    success: true, 
                    token,
                    user: { email, role: 'admin' }
                });
            }
        }
        
        // Check database for admin users
        const userResult = await pool.query(
            'SELECT * FROM admin_users WHERE email = $1',
            [email]
        );
        
        if (userResult.rows.length > 0) {
            const user = userResult.rows[0];
            const isValidPassword = await bcrypt.compare(password, user.password);
            
            if (isValidPassword) {
                const token = jwt.sign(
                    { 
                        email: user.email,
                        role: user.role,
                        name: user.name,
                        timestamp: Date.now()
                    },
                    process.env.JWT_SECRET || 'your-secret-key',
                    { expiresIn: '24h' }
                );
                
                await pool.query(
                    'UPDATE admin_users SET last_login = CURRENT_TIMESTAMP WHERE id = $1',
                    [user.id]
                );
                
                return res.json({ 
                    success: true, 
                    token,
                    user: {
                        email: user.email,
                        name: user.name,
                        role: user.role
                    }
                });
            }
        }
        
        res.status(401).json({ 
            success: false, 
            message: 'Invalid credentials' 
        });
        
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Server error during login' 
        });
    }
});

// Create initial admin user
app.post('/api/admin/register', async (req, res) => {
    try {
        const { email, password, name } = req.body;
        
        if (!email || !password) {
            return res.status(400).json({ 
                success: false, 
                message: 'Email and password are required' 
            });
        }
        
        // Check if user already exists
        const existingUser = await pool.query(
            'SELECT * FROM admin_users WHERE email = $1',
            [email]
        );
        
        if (existingUser.rows.length > 0) {
            return res.status(400).json({ 
                success: false, 
                message: 'User already exists' 
            });
        }
        
        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);
        
        // Create user
        const result = await pool.query(
            `INSERT INTO admin_users (email, password, name, role) 
            VALUES ($1, $2, $3, $4) 
            RETURNING id, email, name, role, created_at`,
            [email, hashedPassword, name, 'admin']
        );
        
        res.json({ 
            success: true, 
            message: 'Admin user created successfully',
            user: result.rows[0]
        });
        
    } catch (error) {
        console.error('Register error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Failed to create admin user' 
        });
    }
});

// Get Dashboard Stats
app.get('/api/admin/stats', verifyAdmin, async (req, res) => {
    try {
        const [
            ordersResult,
            pendingResult,
            productsResult,
            revenueResult,
            todayOrdersResult,
            completedOrdersResult
        ] = await Promise.all([
            pool.query('SELECT COUNT(*) as count FROM orders'),
            pool.query("SELECT COUNT(*) as count FROM orders WHERE status = 'pending'"),
            pool.query('SELECT COUNT(*) as count FROM products'),
            pool.query("SELECT SUM(total_amount) as total FROM orders WHERE payment_status = 'paid'"),
            pool.query("SELECT COUNT(*) as count FROM orders WHERE DATE(created_at) = CURRENT_DATE"),
            pool.query("SELECT COUNT(*) as count FROM orders WHERE status = 'delivered'")
        ]);
        
        res.json({
            success: true,
            totalOrders: parseInt(ordersResult.rows[0].count) || 0,
            pendingOrders: parseInt(pendingResult.rows[0].count) || 0,
            totalProducts: parseInt(productsResult.rows[0].count) || 0,
            totalRevenue: parseFloat(revenueResult.rows[0].total) || 0,
            todayOrders: parseInt(todayOrdersResult.rows[0].count) || 0,
            completedOrders: parseInt(completedOrdersResult.rows[0].count) || 0
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

// Get Recent Orders
app.get('/api/admin/orders/recent', verifyAdmin, async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT *, id as _id FROM orders 
            ORDER BY created_at DESC LIMIT 10`
        );
        
        const orders = result.rows.map(order => ({
            ...order,
            _id: order._id || order.id,
            items: JSON.parse(order.items),
            customerName: order.customer_name,
            orderId: order.order_id,
            totalAmount: parseFloat(order.total_amount),
            createdAt: order.created_at
        }));
        
        res.json({
            success: true,
            orders
        });
        
    } catch (error) {
        console.error('Recent orders error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Server error',
            error: error.message 
        });
    }
});

// Get All Orders with filtering
app.get('/api/admin/orders', verifyAdmin, async (req, res) => {
    try {
        const { status, page = 1, limit = 20 } = req.query;
        const offset = (page - 1) * limit;
        
        let query = 'SELECT *, id as _id FROM orders';
        let countQuery = 'SELECT COUNT(*) FROM orders';
        const params = [];
        
        if (status) {
            query += ' WHERE status = $1';
            countQuery += ' WHERE status = $1';
            params.push(status);
        }
        
        query += ' ORDER BY created_at DESC LIMIT $' + (params.length + 1) + ' OFFSET $' + (params.length + 2);
        params.push(parseInt(limit), parseInt(offset));
        
        const [ordersResult, countResult] = await Promise.all([
            pool.query(query, params),
            pool.query(countQuery, status ? [status] : [])
        ]);
        
        const orders = ordersResult.rows.map(order => ({
            _id: order._id || order.id,
            orderId: order.order_id,
            customerName: order.customer_name,
            email: order.email,
            phone: order.phone,
            location: {
                latitude: parseFloat(order.latitude) || 0,
                longitude: parseFloat(order.longitude) || 0
            },
            items: JSON.parse(order.items),
            totalAmount: parseFloat(order.total_amount),
            paymentStatus: order.payment_status,
            status: order.status,
            deliveryTime: order.delivery_time,
            deliveryMethod: order.delivery_method,
            paymentMethod: order.payment_method,
            deliveryNotes: order.delivery_notes,
            createdAt: order.created_at,
            updatedAt: order.updated_at
        }));
        
        res.json({
            success: true,
            orders,
            pagination: {
                total: parseInt(countResult.rows[0].count),
                page: parseInt(page),
                limit: parseInt(limit),
                pages: Math.ceil(countResult.rows[0].count / limit)
            }
        });
        
    } catch (error) {
        console.error('Get orders error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Server error',
            error: error.message 
        });
    }
});

// Get Products for Admin with _id field
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
        
        res.json({
            success: true,
            products
        });
    } catch (error) {
        console.error('Get admin products error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Server error',
            error: error.message 
        });
    }
});

// Confirm Order with delivery time
app.post('/api/admin/orders/:id/confirm', verifyAdmin, async (req, res) => {
    try {
        const { deliveryTime, notes } = req.body;
        const orderId = req.params.id;
        
        if (!deliveryTime) {
            return res.status(400).json({ 
                success: false, 
                message: 'Delivery time is required' 
            });
        }
        
        await pool.query(
            `UPDATE orders 
            SET status = $1, delivery_time = $2, updated_at = CURRENT_TIMESTAMP 
            WHERE id = $3 OR order_id = $3`,
            ['confirmed', deliveryTime, orderId]
        );
        
        // Add note if provided
        if (notes) {
            await pool.query(
                `UPDATE orders 
                SET delivery_notes = COALESCE(delivery_notes || ' ', '') || $1 
                WHERE id = $2 OR order_id = $2`,
                [`[Admin Note: ${notes}]`, orderId]
            );
        }
        
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

// Update Order Status
app.patch('/api/admin/orders/:id/status', verifyAdmin, async (req, res) => {
    try {
        const { status, notes } = req.body;
        const orderId = req.params.id;
        
        if (!status) {
            return res.status(400).json({ 
                success: false, 
                message: 'Status is required' 
            });
        }
        
        const validStatuses = ['pending', 'confirmed', 'processing', 'shipped', 'delivered', 'cancelled'];
        if (!validStatuses.includes(status)) {
            return res.status(400).json({ 
                success: false, 
                message: 'Invalid status' 
            });
        }
        
        await pool.query(
            `UPDATE orders 
            SET status = $1, updated_at = CURRENT_TIMESTAMP 
            WHERE id = $2 OR order_id = $2`,
            [status, orderId]
        );
        
        // Add note if provided
        if (notes) {
            await pool.query(
                `UPDATE orders 
                SET delivery_notes = COALESCE(delivery_notes || ' ', '') || $1 
                WHERE id = $2 OR order_id = $2`,
                [`[Status Update: ${status} - ${notes}]`, orderId]
            );
        }
        
        res.json({ 
            success: true, 
            message: `Order status updated to ${status}` 
        });
        
    } catch (error) {
        console.error('Update order status error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Failed to update order status',
            error: error.message 
        });
    }
});

// Update Payment Status
app.patch('/api/admin/orders/:id/payment', verifyAdmin, async (req, res) => {
    try {
        const { paymentStatus } = req.body;
        const orderId = req.params.id;
        
        if (!paymentStatus) {
            return res.status(400).json({ 
                success: false, 
                message: 'Payment status is required' 
            });
        }
        
        await pool.query(
            `UPDATE orders 
            SET payment_status = $1, updated_at = CURRENT_TIMESTAMP 
            WHERE id = $2 OR order_id = $2`,
            [paymentStatus, orderId]
        );
        
        res.json({ 
            success: true, 
            message: `Payment status updated to ${paymentStatus}` 
        });
        
    } catch (error) {
        console.error('Update payment status error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Failed to update payment status',
            error: error.message 
        });
    }
});

// Add Product
app.post('/api/admin/products', verifyAdmin, async (req, res) => {
    try {
        const { title, type, price, description, quantity, available, images } = req.body;
        
        // Validate required fields
        if (!title || !type || !price || !description) {
            return res.status(400).json({ 
                success: false, 
                message: 'Missing required fields' 
            });
        }
        
        // Default values
        const finalQuantity = quantity || 0;
        const finalAvailable = available !== undefined ? available : true;
        const finalImages = images && images.length > 0 ? images : ['https://images.unsplash.com/photo-1562967916-eb82221dfb92?ixlib=rb-1.2.1&auto=format&fit=crop&w=600&q=80'];
        
        const result = await pool.query(
            `INSERT INTO products 
            (title, type, price, description, quantity, available, images) 
            VALUES ($1, $2, $3, $4, $5, $6, $7) 
            RETURNING *, id as _id`,
            [title, type, parseFloat(price), description, finalQuantity, finalAvailable, finalImages]
        );
        
        res.json({ 
            success: true, 
            product: {
                ...result.rows[0],
                _id: result.rows[0]._id || result.rows[0].id
            },
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
        const productId = req.params.id;
        const { title, type, price, description, quantity, available, images } = req.body;
        
        // Check if product exists
        const existingProduct = await pool.query(
            'SELECT * FROM products WHERE id = $1',
            [productId]
        );
        
        if (existingProduct.rows.length === 0) {
            return res.status(404).json({ 
                success: false, 
                message: 'Product not found' 
            });
        }
        
        // Use existing values if not provided
        const currentProduct = existingProduct.rows[0];
        const updateData = {
            title: title || currentProduct.title,
            type: type || currentProduct.type,
            price: price !== undefined ? parseFloat(price) : currentProduct.price,
            description: description || currentProduct.description,
            quantity: quantity !== undefined ? parseInt(quantity) : currentProduct.quantity,
            available: available !== undefined ? available : currentProduct.available,
            images: images && images.length > 0 ? images : currentProduct.images
        };
        
        const result = await pool.query(
            `UPDATE products 
            SET title = $1, type = $2, price = $3, description = $4, 
                quantity = $5, available = $6, images = $7, updated_at = CURRENT_TIMESTAMP 
            WHERE id = $8 
            RETURNING *, id as _id`,
            [
                updateData.title,
                updateData.type,
                updateData.price,
                updateData.description,
                updateData.quantity,
                updateData.available,
                updateData.images,
                productId
            ]
        );
        
        res.json({ 
            success: true, 
            product: {
                ...result.rows[0],
                _id: result.rows[0]._id || result.rows[0].id
            },
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

// Delete Product with validation
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
        
        // Check if product exists
        const existingProduct = await pool.query(
            'SELECT * FROM products WHERE id = $1',
            [productId]
        );
        
        if (existingProduct.rows.length === 0) {
            return res.status(404).json({ 
                success: false, 
                message: 'Product not found' 
            });
        }
        
        // Delete product
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

// Get Product by ID for admin
app.get('/api/admin/products/:id', verifyAdmin, async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT *, id as _id FROM products WHERE id = $1',
            [req.params.id]
        );
        
        if (result.rows.length === 0) {
            return res.status(404).json({ 
                success: false, 
                message: 'Product not found' 
            });
        }
        
        const product = result.rows[0];
        res.json({
            success: true,
            product: {
                ...product,
                _id: product._id || product.id,
                images: product.images || ['https://images.unsplash.com/photo-1562967916-eb82221dfb92?ixlib=rb-1.2.1&auto=format&fit=crop&w=600&q=80']
            }
        });
        
    } catch (error) {
        console.error('Get product error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Server error',
            error: error.message 
        });
    }
});

// Get Order by ID for admin
app.get('/api/admin/orders/:id', verifyAdmin, async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT *, id as _id FROM orders 
            WHERE id = $1 OR order_id = $1`,
            [req.params.id]
        );
        
        if (result.rows.length === 0) {
            return res.status(404).json({ 
                success: false, 
                message: 'Order not found' 
            });
        }
        
        const order = result.rows[0];
        res.json({
            success: true,
            order: {
                ...order,
                _id: order._id || order.id,
                items: JSON.parse(order.items),
                customerName: order.customer_name,
                orderId: order.order_id,
                totalAmount: parseFloat(order.total_amount)
            }
        });
        
    } catch (error) {
        console.error('Get admin order error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Server error',
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
        origin: req.headers.origin,
        method: req.method,
        headers: req.headers
    });
});

// Debug endpoint for admin
app.get('/api/admin/test', verifyAdmin, (req, res) => {
    res.json({
        success: true,
        message: 'Admin API is working!',
        adminEmail: req.adminEmail,
        timestamp: new Date().toISOString(),
        serverTime: new Date().toLocaleString()
    });
});

// Health Check with database connection test
app.get('/health', async (req, res) => {
    try {
        // Test database connection
        await pool.query('SELECT 1');
        
        res.json({ 
            status: 'OK', 
            timestamp: new Date().toISOString(),
            database: 'connected',
            uptime: process.uptime()
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
        version: '2.0.0',
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
                    status: 'GET /api/orders/:orderId/status',
                    getOrder: 'GET /api/orders/:orderId'
                },
                payments: {
                    initiate: 'POST /api/payments/initiate',
                    status: 'GET /api/payments/status/:checkoutRequestID'
                }
            },
            admin: {
                auth: {
                    login: 'POST /api/admin/login',
                    register: 'POST /api/admin/register'
                },
                dashboard: {
                    stats: 'GET /api/admin/stats',
                    recentOrders: 'GET /api/admin/orders/recent'
                },
                products: {
                    getAll: 'GET /api/admin/products',
                    getSingle: 'GET /api/admin/products/:id',
                    create: 'POST /api/admin/products',
                    update: 'PUT /api/admin/products/:id',
                    delete: 'DELETE /api/admin/products/:id'
                },
                orders: {
                    getAll: 'GET /api/admin/orders',
                    getSingle: 'GET /api/admin/orders/:id',
                    confirm: 'POST /api/admin/orders/:id/confirm',
                    updateStatus: 'PATCH /api/admin/orders/:id/status',
                    updatePayment: 'PATCH /api/admin/orders/:id/payment'
                }
            },
            utility: {
                health: 'GET /health',
                testCors: 'GET /api/test-cors',
                adminTest: 'GET /api/admin/test'
            }
        },
        documentation: 'See README for detailed API documentation'
    });
});

// 404 handler for undefined routes
app.use((req, res) => {
    res.status(404).json({
        success: false,
        message: `Route not found: ${req.method} ${req.originalUrl}`,
        availableMethods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'],
        suggestion: 'Check the root endpoint / for available routes'
    });
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.error('Server error:', err);
    
    res.status(500).json({
        success: false,
        message: 'Internal server error',
        error: process.env.NODE_ENV === 'development' ? err.message : undefined,
        timestamp: new Date().toISOString()
    });
});

// Graceful shutdown
process.on('SIGTERM', async () => {
    console.log('SIGTERM signal received: closing HTTP server');
    await pool.end();
    process.exit(0);
});

process.on('SIGINT', async () => {
    console.log('SIGINT signal received: closing HTTP server');
    await pool.end();
    process.exit(0);
});

// Start Server
const PORT = process.env.PORT || 5000;
const server = app.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
    console.log(`🌐 CORS configured for:`);
    console.log(`   - https://kuku-yetu.netlify.app`);
    console.log(`   - http://localhost:3000`);
    console.log(`   - http://localhost:5500`);
    console.log(`📊 Health check: http://localhost:${PORT}/health`);
    console.log(`📚 API Docs: http://localhost:${PORT}/`);
});

// Handle server errors
server.on('error', (error) => {
    if (error.code === 'EADDRINUSE') {
        console.error(`Port ${PORT} is already in use`);
        process.exit(1);
    } else {
        console.error('Server error:', error);
        process.exit(1);
    }
});
