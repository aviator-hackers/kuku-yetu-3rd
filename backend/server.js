const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();

// Middleware
app.use(cors({
    origin: ['https://kuku-yetu.netlify.app', 'http://localhost:3000', 'http://localhost:5500', 'http://127.0.0.1:5500'],
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
}));

app.options('*', cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));

// Database Connection
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
});

// Initialize Database
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
                status VARCHAR(20) DEFAULT 'pending',
                delivery_time VARCHAR(100),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);

        await pool.query(`
            CREATE TABLE IF NOT EXISTS admin_users (
                id SERIAL PRIMARY KEY,
                email VARCHAR(255) UNIQUE NOT NULL,
                password VARCHAR(255) NOT NULL,
                name VARCHAR(255) DEFAULT 'Admin',
                role VARCHAR(50) DEFAULT 'admin',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);

        // Create default admin user if not exists
        const adminExists = await pool.query(
            'SELECT * FROM admin_users WHERE email = $1',
            ['admin@kukuyetu.com']
        );

        if (adminExists.rows.length === 0) {
            const hashedPassword = await bcrypt.hash('YourSecurePassword123!', 10);
            await pool.query(
                'INSERT INTO admin_users (email, password, name) VALUES ($1, $2, $3)',
                ['admin@kukuyetu.com', hashedPassword, 'Admin']
            );
            console.log('✅ Default admin user created');
        }

        console.log('✅ Database initialized successfully');
    } catch (error) {
        console.error('❌ Database initialization error:', error);
    }
}

initializeDatabase();

// Admin Middleware
function verifyAdmin(req, res, next) {
    const authHeader = req.headers.authorization;
    
    if (!authHeader) {
        return res.status(401).json({ success: false, message: 'No token provided' });
    }
    
    const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : authHeader;
    
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key');
        req.adminEmail = decoded.email;
        next();
    } catch (error) {
        console.error('Token verification error:', error);
        return res.status(401).json({ success: false, message: 'Invalid token' });
    }
}

// ==================== ADMIN ROUTES ====================

// Admin Login - FIXED
app.post('/api/admin/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        
        if (!email || !password) {
            return res.status(400).json({ 
                success: false, 
                message: 'Email and password are required' 
            });
        }

        console.log('Login attempt for:', email);
        
        // Check environment variables first
        if (process.env.ADMIN_EMAIL && process.env.ADMIN_PASSWORD) {
            console.log('Checking env credentials...');
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
                
                console.log('✅ Login successful via env');
                return res.json({ 
                    success: true, 
                    token,
                    user: { email, role: 'admin' }
                });
            }
        }
        
        // Check database for admin users
        console.log('Checking database credentials...');
        const userResult = await pool.query(
            'SELECT * FROM admin_users WHERE email = $1',
            [email]
        );
        
        if (userResult.rows.length > 0) {
            const user = userResult.rows[0];
            console.log('User found:', user.email);
            
            // Compare passwords
            const isValidPassword = await bcrypt.compare(password, user.password);
            console.log('Password valid:', isValidPassword);
            
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
                
                console.log('✅ Login successful via database');
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
        
        console.log('❌ Invalid credentials');
        res.status(401).json({ 
            success: false, 
            message: 'Invalid email or password' 
        });
        
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Server error during login' 
        });
    }
});

// Create admin user (for testing)
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
            [email, hashedPassword, name || 'Admin', 'admin']
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
            revenueResult
        ] = await Promise.all([
            pool.query('SELECT COUNT(*) as count FROM orders'),
            pool.query("SELECT COUNT(*) as count FROM orders WHERE status = 'pending'"),
            pool.query('SELECT COUNT(*) as count FROM products'),
            pool.query("SELECT SUM(total_amount) as total FROM orders WHERE payment_status = 'paid'")
        ]);
        
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
            message: 'Server error' 
        });
    }
});

// Get Recent Orders
app.get('/api/admin/orders/recent', verifyAdmin, async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT * FROM orders 
            ORDER BY created_at DESC LIMIT 10`
        );
        
        const orders = result.rows.map(order => ({
            order_id: order.order_id,
            customer_name: order.customer_name,
            items: JSON.parse(order.items),
            total_amount: parseFloat(order.total_amount),
            status: order.status,
            created_at: order.created_at
        }));
        
        res.json(orders);
        
    } catch (error) {
        console.error('Recent orders error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Server error'
        });
    }
});

// Get All Orders
app.get('/api/admin/orders', verifyAdmin, async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT * FROM orders ORDER BY created_at DESC'
        );
        
        const orders = result.rows.map(order => ({
            id: order.id,
            _id: order.id,
            orderId: order.order_id,
            order_id: order.order_id,
            customer_name: order.customer_name,
            customerName: order.customer_name,
            email: order.email,
            phone: order.phone,
            latitude: parseFloat(order.latitude),
            longitude: parseFloat(order.longitude),
            items: JSON.parse(order.items),
            total_amount: parseFloat(order.total_amount),
            totalAmount: parseFloat(order.total_amount),
            payment_status: order.payment_status,
            status: order.status,
            delivery_time: order.delivery_time,
            created_at: order.created_at,
            createdAt: order.created_at
        }));
        
        res.json(orders);
        
    } catch (error) {
        console.error('Get orders error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Server error'
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
            SET status = 'confirmed', delivery_time = $1 
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
            message: 'Failed to confirm order'
        });
    }
});

// Get Products
app.get('/api/admin/products', verifyAdmin, async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT * FROM products ORDER BY created_at DESC'
        );
        
        const products = result.rows.map(product => ({
            id: product.id,
            _id: product.id,
            title: product.title,
            type: product.type,
            price: parseFloat(product.price),
            description: product.description,
            quantity: parseInt(product.quantity),
            available: product.available,
            images: product.images || ['https://images.unsplash.com/photo-1562967916-eb82221dfb92'],
            created_at: product.created_at,
            createdAt: product.created_at
        }));
        
        res.json(products);
    } catch (error) {
        console.error('Get products error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Server error'
        });
    }
});

// Add Product
app.post('/api/admin/products', verifyAdmin, async (req, res) => {
    try {
        const { title, type, price, description, quantity, available, images } = req.body;
        
        if (!title || !type || !price || !description) {
            return res.status(400).json({ 
                success: false, 
                message: 'Missing required fields' 
            });
        }
        
        const result = await pool.query(
            `INSERT INTO products 
            (title, type, price, description, quantity, available, images) 
            VALUES ($1, $2, $3, $4, $5, $6, $7) 
            RETURNING *`,
            [title, type, parseFloat(price), description, quantity || 0, available !== false, images || []]
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
            message: 'Failed to add product'
        });
    }
});

// Update Product
app.put('/api/admin/products/:id', verifyAdmin, async (req, res) => {
    try {
        const productId = req.params.id;
        const { title, type, price, description, quantity, available, images } = req.body;
        
        const result = await pool.query(
            `UPDATE products 
            SET title = $1, type = $2, price = $3, description = $4, 
                quantity = $5, available = $6, images = $7, updated_at = CURRENT_TIMESTAMP 
            WHERE id = $8 
            RETURNING *`,
            [title, type, parseFloat(price), description, quantity, available, images, productId]
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
            message: 'Failed to update product'
        });
    }
});

// Delete Product
app.delete('/api/admin/products/:id', verifyAdmin, async (req, res) => {
    try {
        const productId = req.params.id;
        
        await pool.query('DELETE FROM products WHERE id = $1', [productId]);
        
        res.json({ 
            success: true, 
            message: 'Product deleted successfully' 
        });
        
    } catch (error) {
        console.error('Delete product error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Failed to delete product'
        });
    }
});

// ==================== PUBLIC ROUTES ====================

// Get Products
app.get('/api/products', async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT * FROM products WHERE available = true ORDER BY created_at DESC'
        );
        
        const products = result.rows.map(product => ({
            _id: product.id,
            id: product.id,
            title: product.title,
            type: product.type,
            price: parseFloat(product.price),
            description: product.description,
            quantity: parseInt(product.quantity),
            available: product.available,
            images: product.images || ['https://images.unsplash.com/photo-1562967916-eb82221dfb92']
        }));
        
        res.json(products);
    } catch (error) {
        console.error('Get products error:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// Create Order
app.post('/api/orders', async (req, res) => {
    try {
        const { 
            fullName, 
            email, 
            phone, 
            latitude, 
            longitude, 
            items, 
            totalAmount 
        } = req.body;
        
        const orderId = `KY${Date.now()}${Math.floor(Math.random() * 1000)}`;
        
        const result = await pool.query(
            `INSERT INTO orders 
            (order_id, customer_name, email, phone, latitude, longitude, items, total_amount) 
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8) 
            RETURNING *`,
            [
                orderId,
                fullName,
                email,
                phone,
                latitude,
                longitude,
                JSON.stringify(items),
                totalAmount
            ]
        );
        
        res.json({
            success: true,
            orderId: orderId,
            order: result.rows[0]
        });
        
    } catch (error) {
        console.error('Create order error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Failed to create order'
        });
    }
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
            database: 'disconnected'
        });
    }
});

// Start Server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
    console.log(`🌐 Health check: https://kuku-yetu-3rd.onrender.com/health`);
    console.log(`🔐 Admin login: https://kuku-yetu-3rd.onrender.com/api/admin/login`);
});
