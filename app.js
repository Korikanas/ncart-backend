require('dotenv').config(); 
const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
app.use(cors());
app.use(express.json());

// Connect to MongoDB (Railway or local)
mongoose.connect(process.env.MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
})
.then(() => console.log('Connected to MongoDB'))
.catch(err => console.log('MongoDB connection error:', err));

// JWT Secret from environment variable
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';

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
  cancellationReason: {
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
      // ========== 7m DELIVERY PRODUCTS ==========
      {
        name: "Emergency Phone Charger",
        price: 299,
        description: "Portable power bank with 7-minute delivery",
        category: "7m",
        img: "img/Emergency Phone Charger.webp",
        rating: 4.5,
        reviews: 120,
        deliveryTime: "7m"
      },
      {
        name: "Instant Snack Pack",
        price: 149,
        description: "Assorted snacks delivered within 7 minutes",
        category: "7m",
        img: "img/Instant Snack Pack.jpg",
        rating: 4.2,
        reviews: 85,
        deliveryTime: "7m"
      },
      {
        name: "Express Coffee Pack",
        price: 199,
        description: "Premium coffee beans with 7-minute delivery",
        category: "7m",
        img: "img/Express Coffee Pack.jpg",
        rating: 4.7,
        reviews: 200,
        deliveryTime: "7m"
      },
      {
        name: "First Aid Kit",
        price: 399,
        description: "Emergency medical supplies with 7-minute delivery",
        category: "7m",
        img: "img/First Aid Kit.jpg",
        rating: 4.8,
        reviews: 150,
        deliveryTime: "7m"
      },
      {
        name: "Emergency Medicines Kit",
        price: 599,
        description: "Essential medicines delivered in 7 minutes",
        category: "7m",
        img: "img/Emergency Medicines Kit.avif",
        rating: 4.9,
        reviews: 300,
        deliveryTime: "7m"
      },
      {
        name: "Quick Meal Box",
        price: 249,
        description: "Ready-to-eat meal delivered in 7 minutes",
        category: "7m",
        img: "img/Quick Meal Box.webp",
        rating: 4.3,
        reviews: 180,
        deliveryTime: "7m"
      },
      {
        name: "Emergency Water Bottles",
        price: 99,
        description: "Pack of 6 mineral water bottles in 7 minutes",
        category: "7m",
        img: "img/Emergency Water Bottles.jpg",
        rating: 4.6,
        reviews: 220,
        deliveryTime: "7m"
      },
      {
        name: "Phone Screen Protector",
        price: 199,
        description: "Tempered glass screen protector in 7 minutes",
        category: "7m",
        img: "img/Phone Screen Protector.jpg",
        rating: 4.4,
        reviews: 160,
        deliveryTime: "7m"
      },

      // ========== REGULAR PRODUCTS (from your products.js) ==========
      {
        name: "SAMSUNG Galaxy S22 5G (8GB/128GB)",
        price: 59999,
        description: "6.1” FHD+ | 50MP | 3700 mAh | Snapdragon 8 Gen 1",
        category: "new",
        img: "img/s22.jpg",
        rating: 5,
        reviews: 725,
        deliveryTime: "2-3 days"
      },
      {
        name: "Samsung Watch 5 Pro LTE",
        price: 49999,
        description: "AMOLED | LTE calling | GPS | Titanium",
        category: "Gadgets",
        img: "img/Samsung Watch.jpg",
        rating: 5,
        reviews: 75,
        deliveryTime: "2-3 days"
      },
      {
        name: "Samsung Galaxy S24 Ultra 5G (256 GB)",
        price: 129999,
        description: "6.8\" QHD+ | Snapdragon 8 Gen 3 | 200MP + 50MP + 12MP + 10MP",
        category: "Mobiles",
        img: "img/s24.jpg",
        rating: 4.9,
        reviews: 950,
        deliveryTime: "2-3 days"
      },
      {
        name: "iPhone 16 Pro Max (256 GB)",
        price: 149990,
        description: "48MP + 12MP + 12MP | A18 Pro | 6.9\" LTPO OLED",
        category: "Mobiles",
        img: "img/16pro.webp",
        rating: 5,
        reviews: 1100,
        deliveryTime: "2-3 days"
      },
      {
        name: "Xiaomi 14 CIVI (12/512)",
        price: 47999,
        description: "6.55” | 50MP | 4700 mAh | 8s Gen 3",
        category: "Mobiles",
        img: "img/Xiaomi14Civi.jpg",
        rating: 5,
        reviews: 127,
        deliveryTime: "2-3 days"
      },
      {
        name: "OnePlus 11R 5G (16/256)",
        price: 38760,
        description: "6.7” | 50MP | 5000 mAh",
        category: "Mobiles",
        img: "img/11-R.jpg",
        rating: 5,
        reviews: 122,
        deliveryTime: "2-3 days"
      },
      {
        name: "Google Pixel 7a (8/128)",
        price: 36999,
        description: "6.1\" FHD+ | 64MP OIS | Tensor G2",
        category: "Mobiles",
        img: "img/google-pixel-7a.jpg",
        rating: 5,
        reviews: 201,
        deliveryTime: "2-3 days"
      },
      {
        name: "MacBook Pro (M3 Pro, 14\")",
        price: 187990,
        description: "18GB/512GB | macOS Sonoma",
        category: "Laptops",
        img: "img/macbook-pro.jpg",
        rating: 5,
        reviews: 7,
        deliveryTime: "3-4 days"
      },
      {
        name: "Samsung Galaxy Book3 i5 (16\")",
        price: 131391,
        description: "16GB/512GB | Win 11 Home",
        category: "Laptops",
        img: "img/book3.jpg",
        rating: 5,
        reviews: 123,
        deliveryTime: "3-4 days"
      },
      {
        name: "Dell XPS 13 (9340)",
        price: 154990,
        description: "16GB/512GB | Windows 11 Pro",
        category: "Laptops",
        img: "img/xps13.jpg",
        rating: 4,
        reviews: 89,
        deliveryTime: "3-4 days"
      },
      {
        name: "HP Envy x360 2-in-1",
        price: 114990,
        description: "16GB/1TB | Windows 11 Home",
        category: "Laptops",
        img: "img/envy-x360.jpg",
        rating: 4,
        reviews: 67,
        deliveryTime: "3-4 days"
      },
      {
        name: "Lenovo Slim 7 Pro X",
        price: 127490,
        description: "32GB/1TB | Windows 11 Home",
        category: "Laptops",
        img: "img/lenovo-slim7.jpg",
        rating: 5,
        reviews: 145,
        deliveryTime: "3-4 days"
      },
      {
        name: "ASUS Zenbook 14 OLED",
        price: 99990,
        description: "16GB/512GB | Windows 11 Home",
        category: "Laptops",
        img: "img/zenbook14.jpg",
        rating: 4,
        reviews: 200,
        deliveryTime: "3-4 days"
      },
      {
        name: "MSI Cyborg 15 (RTX 4060)",
        price: 119990,
        description: "16GB/512GB | Windows 11 Home",
        category: "Laptops",
        img: "img/cyborg15.jpg",
        rating: 4,
        reviews: 74,
        deliveryTime: "3-4 days"
      },
      {
        name: "Acer Swift Go 14",
        price: 87990,
        description: "16GB/512GB | Windows 11 Home",
        category: "Laptops",
        img: "img/swiftgo14.jpg",
        rating: 4,
        reviews: 52,
        deliveryTime: "3-4 days"
      },
      {
        name: "Unitree Go2 Robot Dog Quadruped Robotics",
        price: 899999,
        description: "AI Mobility | 4D LIDAR | Autonomous Navigation",
        category: "new",
        img: "img/dog.jpg",
        rating: 4.8,
        reviews: 312,
        deliveryTime: "5-7 days"
      },
      {
        name: "Logitech K480 Multidevice Bluetooth Tablet Keyboard",
        price: 2999,
        description: "Multi-Device | Easy-Switch Dial | Built-in Cradle",
        category: "Gadgets",
        img: "img/keybord.jpg",
        rating: 4.5,
        reviews: 1485,
        deliveryTime: "2-3 days"
      },
      {
        name: "iPhone 15 Pro Max (256 GB)",
        price: 139990,
        description: "6.7\" Super Retina XDR | A17 Pro | 48MP",
        category: "new",
        img: "img/iPhone_15.jpg",
        rating: 5,
        reviews: 1235,
        deliveryTime: "2-3 days"
      },
      {
        name: "Sony FX6 Cinema Line Full-Frame Digital Zoom Camera",
        price: 499999,
        description: "4K Full-Frame | Fast Hybrid AF | Professional Video",
        category: "new",
        img: "img/cam.jpg",
        rating: 4.9,
        reviews: 274,
        deliveryTime: "5-7 days"
      },
      {
        name: "Spigen 10000 mAh MagSafe",
        price: 2399,
        description: "20W Wireless | Ultra-compact",
        category: "Gadgets",
        img: "img/Spigen.jpg",
        rating: 5,
        reviews: 764,
        deliveryTime: "2-3 days"
      },
      {
        name: "Samsung Galaxy Buds 3 (Silver)",
        price: 13850,
        description: "24-bit Hi-Fi | up to 36H | IP57",
        category: "new",
        img: "img/buds.avif",
        rating: 4,
        reviews: 451,
        deliveryTime: "2-3 days"
      },
      {
        name: "DJI Avata 2 Fly More Combo",
        price: 139000,
        description: "4K | Built‑in Prop Guard | POV",
        category: "new",
        img: "img/dji.jpg",
        rating: 5,
        reviews: 734,
        deliveryTime: "3-4 days"
      },
      {
        name: "Meta Quest 3 (512GB)",
        price: 64990,
        description: "Mixed Reality | Quest+ Bundle",
        category: "new",
        img: "img/meta.jpg",
        rating: 4,
        reviews: 787,
        deliveryTime: "3-4 days"
      },
      {
        name: "Apple AirPods Max (Sky Blue)",
        price: 59899,
        description: "Bluetooth | Smart Case | USB‑C to Lightning",
        category: "new",
        img: "img/Airpods.webp",
        rating: 5,
        reviews: 70,
        deliveryTime: "2-3 days"
      }

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
    
       // ========== blog ==========
{
        title: "The Future of Smartphones: What to Expect in 2024",
        excerpt: "Discover the latest trends and innovations in smartphone technology for the coming year.",
        content: "The smartphone industry is constantly evolving, with new features and technologies emerging every year. In 2024, we expect to see foldable phones becoming more mainstream, improved battery technology, and enhanced AI capabilities that will revolutionize how we interact with our devices.",
        author: "Tech Insider",
        date: "2024-01-15",
        category: "Mobiles",
        image: "img/Best-phones-202.avif"
      },
      {
        title: "Top 5 Laptops for Professionals in 2024",
        excerpt: "Find the perfect laptop for your professional needs with our comprehensive guide.",
        content: "Choosing the right laptop for professional work can be challenging. We've tested and reviewed the top models from leading brands to help you make an informed decision. From powerful processors to stunning displays, these laptops offer the best performance for business and creative work.",
        author: "Product Review Team",
        date: "2024-01-10",
        category: "Laptops",
        image: "img/laptop blog.jpg"
      },
      {
        title: "Essential Gadgets for Digital Nomads",
        excerpt: "Must-have tech gadgets for those who work and travel simultaneously.",
        content: "Digital nomads need reliable and portable gadgets to stay productive while on the move. From compact keyboards to portable monitors and power banks, we've compiled a list of essential gadgets that will make your nomadic lifestyle easier and more efficient.",
        author: "Travel Tech",
        date: "2024-01-05",
        category: "Gadgets",
        image: "img/blog_gadgets.jpg"
      },
      {
        title: "How to Extend Your Phone Battery Life",
        excerpt: "Practical tips to maximize your smartphone battery performance.",
        content: "Battery life is a common concern for smartphone users. By adjusting settings, managing apps, and following best practices, you can significantly extend your phone's battery life. Learn about the most effective strategies to keep your device powered throughout the day.",
        author: "Tech Tips",
        date: "2023-12-28",
        category: "Mobiles",
        image: "img/battery.jpg"
      },
      {
        title: "The Rise of Wearable Technology",
        excerpt: "Exploring how wearable tech is changing our daily lives.",
        content: "Wearable technology has evolved from simple fitness trackers to sophisticated health monitors and smart clothing. This article explores the latest advancements in wearable tech and how these devices are integrating into our everyday routines.",
        author: "Tech Trends",
        date: "2023-12-20",
        category: "Gadgets",
        image: "img/feature_image.jpg"
      },
      {
        title: "Gaming Laptops vs Desktop Setups: Which is Better?",
        excerpt: "A comparison of gaming laptops and desktop computers for avid gamers.",
        content: "The debate between gaming laptops and desktop setups continues among gaming enthusiasts. While laptops offer portability, desktops provide more power and customization options. We break down the pros and cons of each to help you decide which is right for your gaming needs.",
        author: "Gaming Expert",
        date: "2023-12-15",
        category: "Laptops",
        image: "img/vs.jpg"
      }
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

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    message: 'Server is running',
    database: mongoose.connection.readyState === 1 ? 'Connected' : 'Disconnected'
  });
});

// Start server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Backend running on http://localhost:${PORT}`);
});