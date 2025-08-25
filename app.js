const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
app.use(cors());
app.use(express.json());

// Connect to MongoDB
mongoose.connect('mongodb://localhost:27017/Ncart');

// JWT Secret (should be in environment variable in production)
const JWT_SECRET = 'your-secret-key';

// User schema
const User = mongoose.model('User', {
  firstName: String,
  lastName: String,
  email: { type: String, unique: true },
  password: String,
  phone: String,
  dateOfBirth: String,
  gender: String,
  address: String,
  city: String,
  state: String,
  zipCode: String,
  country: String,
  orders: { type: Number, default: 0 },
  profileImage: String,
  createdAt: { type: Date, default: Date.now }
});

// Product schema
const Product = mongoose.model('Product', {
  name: String,
  price: Number,
  description: String,
  category: String,
  img: String,
  rating: Number,
  reviews: Number,
  deliveryTime: String,
});

// Blog Post schema
const BlogPost = mongoose.model('BlogPost', {
  title: String,
  excerpt: String,
  content: String,
  author: String,
  date: String,
  category: String,
  image: String,
});

// Order schema
const Order = mongoose.model('Order', {
  userId: String,
  id: String,
  date: String,
  items: Array,
  total: Number,
  status: String,
  tracking: Object,
  paymentMethod: String,
  address: String,
  cancellationReason: { // Add cancellation reason field
    reason: String,
    comment: String,
    cancelledAt: Date
  }
});

// Middleware to verify JWT token
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid or expired token' });
    }
    req.user = user;
    next();
  });
};

// ========== AUTH ROUTES ==========
// Register new user
app.post('/api/register', async (req, res) => {
  try {
    const { firstName, lastName, email, password, phone, dateOfBirth, gender, address, city, state, zipCode, country } = req.body;

    // Check if user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ error: 'User already exists with this email' });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create new user
    const user = new User({
      firstName,
      lastName,
      email,
      password: hashedPassword,
      phone,
      dateOfBirth,
      gender,
      address,
      city,
      state,
      zipCode,
      country
    });

    await user.save();

    // Generate JWT token
    const token = jwt.sign({ userId: user._id, email: user.email }, JWT_SECRET, { expiresIn: '24h' });

    res.status(201).json({
      message: 'User created successfully',
      token,
      user: {
        id: user._id,
        name: `${firstName} ${lastName}`,
        email: user.email,
        phone: user.phone,
        dateOfBirth: user.dateOfBirth,
        gender: user.gender,
        address: user.address,
        orders: user.orders,
        profileImage: user.profileImage
      }
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Login user
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Find user
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ error: 'Invalid email or password' });
    }

    // Check password
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(400).json({ error: 'Invalid email or password' });
    }

    // Generate JWT token
    const token = jwt.sign({ userId: user._id, email: user.email }, JWT_SECRET, { expiresIn: '24h' });

    res.json({
      message: 'Login successful',
      token,
      user: {
        id: user._id,
        name: `${user.firstName} ${user.lastName}`,
        email: user.email,
        phone: user.phone,
        dateOfBirth: user.dateOfBirth,
        gender: user.gender,
        address: user.address,
        orders: user.orders,
        profileImage: user.profileImage
      }
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Get user profile
app.get('/api/user', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId).select('-password');
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.json(user);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Update user profile
app.put('/api/user', authenticateToken, async (req, res) => {
  try {
    const { firstName, lastName, phone, dateOfBirth, gender, address, city, state, zipCode, country, profileImage } = req.body;
    
    const updatedUser = await User.findByIdAndUpdate(
      req.user.userId,
      { 
        firstName, 
        lastName, 
        phone, 
        dateOfBirth, 
        gender, 
        address, 
        city, 
        state, 
        zipCode, 
        country,
        profileImage
      },
      { new: true }
    ).select('-password');

    res.json(updatedUser);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Change password
app.put('/api/user/password', authenticateToken, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    
    const user = await User.findById(req.user.userId);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Verify current password
    const validPassword = await bcrypt.compare(currentPassword, user.password);
    if (!validPassword) {
      return res.status(400).json({ error: 'Current password is incorrect' });
    }

    // Hash new password
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedPassword;
    await user.save();

    res.json({ message: 'Password updated successfully' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ========== PRODUCT ROUTES ==========
// GET all products
app.get('/api/products', async (req, res) => {
  try {
    const products = await Product.find();
    res.json(products);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET 7m products
app.get('/api/products/7m', async (req, res) => {
  try {
    const products = await Product.find({ 
      $or: [
        { category: '7m' },
        { deliveryTime: '7m' }
      ]
    });
    res.json(products);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST product
app.post('/api/products', async (req, res) => {
  try {
    const product = new Product(req.body);
    await product.save();
    res.status(201).json(product);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// ========== ORDER ROUTES ==========
// Get user orders
app.get('/api/orders', authenticateToken, async (req, res) => {
  try {
    const orders = await Order.find({ userId: req.user.userId }).sort({ date: -1 });
    res.json(orders);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Create new order
app.post('/api/orders', authenticateToken, async (req, res) => {
  try {
    const orderData = {
      ...req.body,
      userId: req.user.userId
    };
    
    const order = new Order(orderData);
    await order.save();
    
    // Update user's order count
    await User.findByIdAndUpdate(req.user.userId, { $inc: { orders: 1 } });
    
    res.status(201).json(order);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Update order status
app.put('/api/orders/:id', authenticateToken, async (req, res) => {
  try {
    const { status, tracking, cancellationReason } = req.body;
    const updateData = { status, tracking };
    
    // If cancelling, add cancellation reason
    if (status === 'Cancelled' && cancellationReason) {
      updateData.cancellationReason = {
        ...cancellationReason,
        cancelledAt: new Date()
      };
    }
    
    const order = await Order.findOneAndUpdate(
      { _id: req.params.id, userId: req.user.userId },
      updateData,
      { new: true }
    );
    
    if (!order) {
      return res.status(404).json({ error: 'Order not found' });
    }
    
    res.json(order);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ========== BLOG ROUTES ==========
// GET all blog posts
app.get('/api/blog', async (req, res) => {
  try {
    const blogPosts = await BlogPost.find().sort({ date: -1 });
    res.json(blogPosts);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET blog post by ID
app.get('/api/blog/:id', async (req, res) => {
  try {
    const blogPost = await BlogPost.findById(req.params.id);
    if (!blogPost) {
      return res.status(404).json({ error: 'Blog post not found' });
    }
    res.json(blogPost);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET blog posts by category
app.get('/api/blog/category/:category', async (req, res) => {
  try {
    const blogPosts = await BlogPost.find({ 
      category: req.params.category 
    }).sort({ date: -1 });
    res.json(blogPosts);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST new blog post
app.post('/api/blog', async (req, res) => {
  try {
    const blogPost = new BlogPost(req.body);
    await blogPost.save();
    res.status(201).json(blogPost);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// ========== ADMIN ROUTES ==========
// Get all users (admin only)
app.get('/api/admin/users', authenticateToken, async (req, res) => {
  try {
    // In a real app, you would check if the user is an admin
    const users = await User.find().select('-password');
    res.json(users);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Get all orders (admin only)
app.get('/api/admin/orders', authenticateToken, async (req, res) => {
  try {
    const orders = await Order.find().sort({ date: -1 });
    res.json(orders);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Update any order (admin only)
app.put('/api/admin/orders/:id', authenticateToken, async (req, res) => {
  try {
    const { status, cancellationReason } = req.body;
    const updateData = { status };
    
    // If cancelling, add cancellation reason
    if (status === 'Cancelled' && cancellationReason) {
      updateData.cancellationReason = {
        ...cancellationReason,
        cancelledAt: new Date()
      };
    }
    
    const order = await Order.findByIdAndUpdate(
      req.params.id,
      updateData,
      { new: true }
    );
    
    if (!order) {
      return res.status(404).json({ error: 'Order not found' });
    }
    
    res.json(order);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Delete product (admin only)
app.delete('/api/admin/products/:id', authenticateToken, async (req, res) => {
  try {
    const product = await Product.findByIdAndDelete(req.params.id);
    
    if (!product) {
      return res.status(404).json({ error: 'Product not found' });
    }
    
    res.json({ message: 'Product deleted successfully' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Delete blog post (admin only)
app.delete('/api/admin/blog/:id', authenticateToken, async (req, res) => {
  try {
    const blogPost = await BlogPost.findByIdAndDelete(req.params.id);
    
    if (!blogPost) {
      return res.status(404).json({ error: 'Blog post not found' });
    }
    
    res.json({ message: 'Blog post deleted successfully' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ========== SEED ROUTES ==========
// Seed products
app.post('/api/seed/products', async (req, res) => {
  try {
    const products = [
      // ... (same as before)
    ];
    
    await Product.deleteMany({});
    await Product.insertMany(products);
    
    res.json({ 
      message: 'Products seeded successfully', 
      count: products.length
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Seed blog posts
app.post('/api/seed/blog', async (req, res) => {
  try {
    const blogPosts = [
      // ... (same as before)
    ];

    await BlogPost.deleteMany({});
    await BlogPost.insertMany(blogPosts);
    
    res.json({ 
      message: 'Blog posts seeded successfully', 
      count: blogPosts.length
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Start server
app.listen(5000, () => {
  console.log('Backend running on http://localhost:5000');
});
