const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const dotenv = require('dotenv');

dotenv.config(); // Load environment variables from .env file

const app = express();
app.use(cors()); // Enable CORS for frontend communication
app.use(express.json()); // Parse JSON bodies

// MongoDB Connection
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('Connected to MongoDB'))
  .catch((err) => console.error('MongoDB connection error:', err));

// Constants for fees and payment
const PLATFORM_FEE = 8;
const GST_RATE = 0.05;
const UPI_ID = process.env.UPI_ID || 'akhileshgarg9630-1@okaxis';
const PAYEE_NAME = process.env.PAYEE_NAME || 'Akhilesh Garg';

const POINTS = [
  { city: 'Sheetal Dham', name: 'Clx1', lat: 23.123806, lng: 77.496402 },
  { city: 'Sheetal Dham', name: 'Clx2', lat: 23.12323, lng: 77.496013 },
  { city: 'Sheetal Dham', name: 'Clx3', lat: 23.122725, lng: 77.495727 },
  { city: 'Sheetal Dham', name: 'Clx4', lat: 23.122734, lng: 77.494585 },
  { city: 'Sheetal Dham', name: 'Clx5', lat: 23.122974, lng: 77.495661 },
  { city: 'Sheetal Dham', name: 'ClxA', lat: 23.124041, lng: 77.496669 },
  { city: 'Chinar Dream City', name: 'Z1', lat: 23.1251109, lng: 77.4916681 },
  { city: 'Chinar Dream City', name: 'Z2', lat: 23.1244599, lng: 77.491643 },
  { city: 'Chinar Dream City', name: 'Z5', lat: 23.123243, lng: 77.491072 },
  { city: 'Chinar Dream City', name: 'Z6', lat: 23.1239869, lng: 77.4905399 },
  { city: 'Chinar Dream City', name: 'Z7', lat: 23.1247661, lng: 77.4900119 },
  { city: 'Chinar Dream City', name: 'Z8', lat: 23.124863, lng: 77.4903451 }
];

// Mongoose Schemas
const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role: { type: String, enum: ['user', 'owner', 'delivery'], required: true },
  blocked: { type: Boolean, default: false },
  likedProducts: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Product' }],
  location: {
    lat: { type: Number },
    lng: { type: Number }
  },
  selectedPoint: {
    name: { type: String },
    lat: { type: Number },
    lng: { type: Number }
  },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now },
});

const categorySchema = new mongoose.Schema({
  name: { type: String, required: true, unique: true },
  imageUrl: { type: String, default: '' },
});

const productSchema = new mongoose.Schema({
  name: { type: String, required: true },
  price: { type: Number, required: true },
  imageUrl: { type: String, default: '' },
  category: { type: String, required: true },
  description: { type: String, default: '' }, // Added description field
  type: { type: String, enum: ['simple', 'offer'], default: 'simple' },
  ratings: [{
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    rating: { type: Number, required: true, min: 1, max: 5 },
    comment: { type: String },
    createdAt: { type: Date, default: Date.now },
    likes: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }]
  }],
  ratingCount: { type: Number, default: 0 },
  averageRating: { type: Number, default: 0 },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now },
});

const orderSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  orderCode: { type: String, required: true }, // Added orderCode
  items: [{
    productId: { type: mongoose.Schema.Types.ObjectId, ref: 'Product', required: true },
    productName: { type: String, required: true },
    price: { type: Number, required: true },
    quantity: { type: Number, required: true, min: 1 },
    imageUrl: { type: String, required: true },
  }],
  subtotal: { type: Number, required: true },
  gst: { type: Number, required: true },
  platformFee: { type: Number, required: true },
  total: { type: Number, required: true },
  status: { type: String, enum: ['draft', 'pending', 'confirmed', 'delivered'], required: true },
  otp: { type: String },
  deliveredBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now },
});

// Track OTP attempts
const otpAttemptsSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  attempts: { type: Number, default: 0 },
  lastAttempt: { type: Date, default: Date.now },
  lockoutsToday: { type: Number, default: 0 },
  lastLockoutDate: { type: Date },
});

const User = mongoose.model('User', userSchema);
const Category = mongoose.model('Category', categorySchema);
const Product = mongoose.model('Product', productSchema);
const Order = mongoose.model('Order', orderSchema);
const OtpAttempts = mongoose.model('OtpAttempts', otpAttemptsSchema);

// Middleware to verify JWT
const authenticate = async (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Unauthorized' });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    res.status(401).json({ error: 'Invalid token' });
  }
};

// OTP Generation
const generateOTP = () => {
  let otp = '';
  let lastDigit = null;
  for (let i = 0; i < 6; i++) {
    let digit;
    do {
      digit = Math.floor(Math.random() * 9) + 1;
    } while (digit === lastDigit);
    otp += digit;
    lastDigit = digit;
  }
  return otp;
};

// Generate 6-character alphanumeric order code (mix of digits and letters)
const generateOrderCode = () => {
  const chars = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  let code = '';
  for (let i = 0; i < 6; i++) {
    code += chars[Math.floor(Math.random() * chars.length)];
  }
  return code;
};

// Initialize default owner
const initializeOwner = async () => {
  const owner = await User.findOne({ email: process.env.OWNER_EMAIL, role: 'owner' });
  if (!owner) {
    const hashedPassword = await bcrypt.hash(process.env.OWNER_PASSWORD, 10);
    await User.create({
      name: 'Admin Owner',
      email: process.env.OWNER_EMAIL,
      password: hashedPassword,
      role: 'owner',
    });
    console.log('Default owner created');
  }
};

// Initialize default products
const initializeProducts = async () => {
  const productCount = await Product.countDocuments();
  if (productCount === 0) {
    await Product.insertMany([
      { name: 'Laptop', price: 50000, imageUrl: 'https://via.placeholder.com/150?text=Laptop', category: 'Electronics', description: 'High performance laptop', type: 'simple' },
      { name: 'Smartphone', price: 20000, imageUrl: 'https://via.placeholder.com/150?text=Smartphone', category: 'Electronics', description: 'Latest smartphone model', type: 'simple' },
      { name: 'Headphones', price: 2000, imageUrl: 'https://via.placeholder.com/150?text=Headphones', category: 'Electronics', description: 'Noise-cancelling headphones', type: 'simple' },
    ]);
    console.log('Default products created');
  }
  const electronicsCat = await Category.findOne({ name: 'Electronics' });
  if (!electronicsCat) {
    await Category.create({ name: 'Electronics', imageUrl: 'https://cdn-icons-png.flaticon.com/512/3659/3659892.png' });
  }
};

// Run initialization on startup
mongoose.connection.once('open', async () => {
  await initializeOwner();
  await initializeProducts();
});

// Register endpoint
app.post('/register', async (req, res) => {
  const { name, email, password, role } = req.body;
  if (!name || !email || !password || !role) {
    return res.status(400).json({ error: 'All fields are required' });
  }
  if (role === 'owner' && email !== process.env.OWNER_EMAIL) {
    return res.status(403).json({ error: 'Owner can only register with ' + process.env.OWNER_EMAIL });
  }

  try {
    const existingUser = await User.findOne({ email, role });
    if (existingUser) {
      return res.status(400).json({ error: 'User already exists with this email and role' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const user = await User.create({ name, email, password: hashedPassword, role });
    res.status(201).json({ message: 'Registration successful' });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Login endpoint
app.post('/login', async (req, res) => {
  const { email, password, role } = req.body;
  if (!email || !password || !role) {
    return res.status(400).json({ error: 'All fields are required' });
  }

  try {
    const user = await User.findOne({ email, role });
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ error: 'Invalid credentials or role' });
    }
    if (user.blocked) {
      return res.status(403).json({ error: 'Account is permanently blocked.' });
    }

    const token = jwt.sign({ userId: user._id, email: user.email, role: user.role }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.json({ token, user: { id: user._id, email: user.email, name: user.name || user.email.split('@')[0], role: user.role } });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Get user profile
app.get('/user/profile', authenticate, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId).select('name email role');
    res.json({ name: user.name || user.email.split('@')[0], email: user.email, role: user.role });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Like/unlike product
app.post('/products/:id/like', authenticate, async (req, res) => {
  if (req.user.role !== 'user') return res.status(403).json({ error: 'Only users can like products' });

  try {
    const user = await User.findById(req.user.userId);
    const productId = req.params.id;
    const index = user.likedProducts.indexOf(productId);
    let liked;
    if (index > -1) {
      user.likedProducts.splice(index, 1);
      liked = false;
    } else {
      user.likedProducts.push(productId);
      liked = true;
    }
    await user.save();
    res.json({ liked });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Get liked products
app.get('/liked', authenticate, async (req, res) => {
  if (req.user.role !== 'user') return res.status(403).json({ error: 'Only users can view liked products' });

  try {
    const user = await User.findById(req.user.userId).populate('likedProducts');
    res.json(user.likedProducts);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Get categories
app.get('/categories', async (req, res) => {
  try {
    let query = {};
    if (req.query.type) query.type = req.query.type;
    const catNames = await Product.distinct('category', query);
    const catNamesSet = new Set(catNames);
    let allCats = [...catNamesSet].sort();
    const cats = await Category.find({ name: { $in: allCats } });
    const catMap = new Map(cats.map(c => [c.name, {imageUrl: c.imageUrl, id: c._id}]));
    const result = allCats.map(name => ({ name, imageUrl: catMap.get(name)?.imageUrl || '', id: catMap.get(name)?.id }));
    result.unshift({ name: 'All', imageUrl: '', id: null });
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Admin categories
app.get('/categories/admin', authenticate, async (req, res) => {
  if (req.user.role !== 'owner') return res.status(403).json({ error: 'Only owners' });
  try {
    let query = {};
    let cats;
    if (req.query.type) {
      query.type = req.query.type;
      const catNames = await Product.distinct('category', query);
      cats = await Category.find({ name: { $in: catNames } });
    } else {
      cats = await Category.find();
    }
    res.json(cats);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/categories', authenticate, async (req, res) => {
  if (req.user.role !== 'owner') return res.status(403).json({ error: 'Only owners' });
  const { name, imageUrl } = req.body;
  if (!name) return res.status(400).json({ error: 'Name required' });
  try {
    const cat = await Category.create({ name, imageUrl: imageUrl || '' });
    res.json(cat);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.put('/categories/:id', authenticate, async (req, res) => {
  if (req.user.role !== 'owner') return res.status(403).json({ error: 'Only owners' });
  const { id } = req.params;
  const { name, imageUrl } = req.body;
  if (!name) return res.status(400).json({ error: 'Name required' });
  try {
    const cat = await Category.findByIdAndUpdate(id, { name, imageUrl: imageUrl || '' }, { new: true });
    if (!cat) return res.status(404).json({ error: 'Not found' });
    res.json(cat);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.delete('/categories/:id', authenticate, async (req, res) => {
  if (req.user.role !== 'owner') return res.status(403).json({ error: 'Only owners' });
  const { id } = req.params;
  try {
    const cat = await Category.findByIdAndDelete(id);
    if (!cat) return res.status(404).json({ error: 'Not found' });
    res.json({ message: 'Deleted' });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Get all products or by category or type
app.get('/products', async (req, res) => {
  try {
    let query = {};
    if (req.query.category && req.query.category !== 'All') {
      query.category = req.query.category;
    }
    if (req.query.type) {
      query.type = req.query.type;
    }
    const products = await Product.find(query);
    res.json(products);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Search products
app.get('/products/search', async (req, res) => {
  const { q } = req.query;
  if (!q) return res.json([]);
  try {
    const products = await Product.find({ name: { $regex: q, $options: 'i' } });
    res.json(products);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Get single product
app.get('/products/:id', async (req, res) => {
  try {
    const product = await Product.findById(req.params.id);
    if (!product) return res.status(404).json({ error: 'Product not found' });
    res.json(product);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Get ratings for a product
app.get('/products/:id/ratings', authenticate, async (req, res) => {
  try {
    const product = await Product.findById(req.params.id).populate('ratings.userId', 'email');
    if (!product) return res.status(404).json({ error: 'Product not found' });
    product.ratings.sort((a, b) => b.createdAt - a.createdAt);
    const ratings = product.ratings.map(r => ({
      ...r._doc,
      likes: r.likes.length,
      likedByMe: r.likes.some(l => l.toString() === req.user.userId)
    }));
    res.json(ratings);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Rate a product (add new always)
app.post('/products/:id/rate', authenticate, async (req, res) => {
  if (req.user.role !== 'user') return res.status(403).json({ error: 'Only users can rate products' });

  const { rating, comment } = req.body;
  if (!rating || rating < 1 || rating > 5) return res.status(400).json({ error: 'Invalid rating' });

  try {
    const product = await Product.findById(req.params.id);
    if (!product) return res.status(404).json({ error: 'Product not found' });

    product.ratings.push({ userId: req.user.userId, rating, comment });
    product.ratingCount = product.ratings.length;
    const sum = product.ratings.reduce((acc, r) => acc + r.rating, 0);
    product.averageRating = (sum / product.ratingCount).toFixed(1);

    await product.save();
    res.json({ message: 'Rating added' });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Like a rating
app.post('/products/:productId/ratings/:ratingId/like', authenticate, async (req, res) => {
  if (req.user.role !== 'user') return res.status(403).json({ error: 'Only users can like ratings' });

  const { productId, ratingId } = req.params;

  try {
    const product = await Product.findById(productId);
    if (!product) return res.status(404).json({ error: 'Product not found' });

    const rating = product.ratings.id(ratingId);
    if (!rating) return res.status(404).json({ error: 'Rating not found' });

    const index = rating.likes.indexOf(req.user.userId);
    let liked;
    if (index > -1) {
      rating.likes.splice(index, 1);
      liked = false;
    } else {
      rating.likes.push(req.user.userId);
      liked = true;
    }

    await product.save();
    res.json({ liked });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Add product (owner only)
app.post('/products', authenticate, async (req, res) => {
  if (req.user.role !== 'owner') {
    return res.status(403).json({ error: 'Only owners can add products' });
  }

  const { name, price, imageUrl, category, description, type } = req.body;
  if (!name || !price || !category) {
    return res.status(400).json({ error: 'Name, price, and category are required' });
  }

  try {
    const product = await Product.create({ name, price, imageUrl, category, description, type });
    // Ensure category exists
    await Category.findOneAndUpdate({ name: category }, { name: category }, { upsert: true });
    res.status(201).json({ message: 'Product added successfully', product });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Edit product (owner only)
app.put('/products/:productId', authenticate, async (req, res) => {
  if (req.user.role !== 'owner') {
    return res.status(403).json({ error: 'Only owners can edit products' });
  }

  const { productId } = req.params;
  const { name, price, imageUrl, category, description, type } = req.body;
  if (!name || !price || !category) {
    return res.status(400).json({ error: 'Name, price, and category are required' });
  }

  try {
    const product = await Product.findByIdAndUpdate(
      productId,
      { name, price, imageUrl, category, description, type, updatedAt: Date.now() },
      { new: true }
    );
    if (!product) {
      return res.status(404).json({ error: 'Product not found' });
    }
    // Ensure category exists
    await Category.findOneAndUpdate({ name: category }, { name: category }, { upsert: true });
    res.json({ message: 'Product updated successfully', product });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Delete product (owner only)
app.delete('/products/:productId', authenticate, async (req, res) => {
  if (req.user.role !== 'owner') {
    return res.status(403).json({ error: 'Only owners can delete products' });
  }

  const { productId } = req.params;
  try {
    const product = await Product.findByIdAndDelete(productId);
    if (!product) {
      return res.status(404).json({ error: 'Product not found' });
    }
    res.json({ message: 'Product deleted successfully' });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Place order with multiple items (user only)
app.post('/orders', authenticate, async (req, res) => {
  if (req.user.role !== 'user') {
    return res.status(403).json({ error: 'Only users can place orders' });
  }

  const { items } = req.body;
  if (!items || !Array.isArray(items) || items.length === 0) {
    return res.status(400).json({ error: 'Items array is required and must not be empty' });
  }

  try {
    const itemsWithDetails = await Promise.all(items.map(async (item) => {
      const product = await Product.findById(item.productId);
      if (!product) {
        throw new Error(`Product ${item.productId} not found`);
      }
      return {
        productId: product._id,
        productName: product.name,
        price: product.price,
        quantity: item.quantity,
        imageUrl: product.imageUrl,
      };
    }));

    const subtotal = itemsWithDetails.reduce((acc, item) => acc + item.price * item.quantity, 0);
    const gst = subtotal * GST_RATE;
    const platformFee = PLATFORM_FEE;
    const total = subtotal + gst + platformFee;
    const orderCode = generateOrderCode();

    const order = await Order.create({
      userId: req.user.userId,
      orderCode,
      items: itemsWithDetails,
      subtotal,
      gst,
      platformFee,
      total,
      status: 'draft',
    });

    res.status(201).json({ message: 'Order placed successfully', order });
  } catch (err) {
    res.status(500).json({ error: err.message || 'Server error' });
  }
});

// Update item quantity in order (user only, draft only)
app.put('/orders/:orderId/items/:productId/quantity', authenticate, async (req, res) => {
  if (req.user.role !== 'user') {
    return res.status(403).json({ error: 'Only users can update quantity' });
  }

  const { orderId, productId } = req.params;
  const { quantity } = req.body;
  if (!quantity || quantity < 1) {
    return res.status(400).json({ error: 'Valid quantity required' });
  }

  try {
    const order = await Order.findById(orderId);
    if (!order) {
      return res.status(404).json({ error: 'Order not found' });
    }
    if (order.userId.toString() !== req.user.userId) {
      return res.status(403).json({ error: 'Not authorized' });
    }
    if (order.status !== 'draft') {
      return res.status(400).json({ error: 'Can only update draft orders' });
    }

    const item = order.items.find(i => i.productId.toString() === productId);
    if (!item) {
      return res.status(404).json({ error: 'Item not found in order' });
    }

    item.quantity = quantity;
    order.subtotal = order.items.reduce((acc, i) => acc + i.price * i.quantity, 0);
    order.gst = order.subtotal * GST_RATE;
    order.total = order.subtotal + order.gst + order.platformFee;
    order.updatedAt = Date.now();
    await order.save();

    res.json({ message: 'Quantity updated', order });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Remove item from order (user only, draft only)
app.delete('/orders/:orderId/items/:productId', authenticate, async (req, res) => {
  if (req.user.role !== 'user') {
    return res.status(403).json({ error: 'Only users can remove items' });
  }

  const { orderId, productId } = req.params;

  try {
    const order = await Order.findById(orderId);
    if (!order) {
      return res.status(404).json({ error: 'Order not found' });
    }
    if (order.userId.toString() !== req.user.userId) {
      return res.status(403).json({ error: 'Not authorized' });
    }
    if (order.status !== 'draft') {
      return res.status(400).json({ error: 'Can only update draft orders' });
    }

    order.items = order.items.filter(i => i.productId.toString() !== productId);
    if (order.items.length === 0) {
      await order.deleteOne();
      return res.json({ message: 'Order deleted as it was empty' });
    }

    order.subtotal = order.items.reduce((acc, i) => acc + i.price * i.quantity, 0);
    order.gst = order.subtotal * GST_RATE;
    order.total = order.subtotal + order.gst + order.platformFee;
    order.updatedAt = Date.now();
    await order.save();

    res.json({ message: 'Item removed', order });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Confirm user order (draft to pending)
app.patch('/orders/:orderId/confirm-user', authenticate, async (req, res) => {
  if (req.user.role !== 'user') {
    return res.status(403).json({ error: 'Only users can confirm orders' });
  }

  const { orderId } = req.params;
  try {
    const order = await Order.findById(orderId);
    if (!order) {
      return res.status(404).json({ error: 'Order not found' });
    }
    if (order.userId.toString() !== req.user.userId) {
      return res.status(403).json({ error: 'Not authorized' });
    }
    if (order.status !== 'draft') {
      return res.status(400).json({ error: 'Can only confirm draft orders' });
    }

    order.status = 'pending';
    order.updatedAt = Date.now();
    await order.save();

    res.json({ message: 'Order confirmed and sent to owner' });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Generate payment for order (user only, after confirmation)
app.post('/orders/:orderId/generate-payment', authenticate, async (req, res) => {
  if (req.user.role !== 'user') {
    return res.status(403).json({ error: 'Only users can generate payment' });
  }

  const { orderId } = req.params;
  try {
    const order = await Order.findById(orderId);
    if (!order) {
      return res.status(404).json({ error: 'Order not found' });
    }
    if (order.userId.toString() !== req.user.userId) {
      return res.status(403).json({ error: 'Not authorized to access this order' });
    }
    if (order.status !== 'pending') {
      return res.status(400).json({ error: 'Order must be pending for payment' });
    }

    const transactionNote = `Payment for order ${orderId} by user ${req.user.userId} email ${req.user.email}`;
    const upiUrl = `upi://pay?pa=${UPI_ID}&pn=${encodeURIComponent(PAYEE_NAME)}&am=${order.total}&tn=${encodeURIComponent(transactionNote)}&cu=INR`;
    const qrSrc = `https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=${encodeURIComponent(upiUrl)}`;

    res.json({ total: order.total, upiUrl, qrSrc });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Get user orders
app.get('/orders/user', authenticate, async (req, res) => {
  if (req.user.role !== 'user') {
    return res.status(403).json({ error: 'Only users can view their orders' });
  }

  try {
    const orders = await Order.find({ userId: req.user.userId }).populate('items.productId');
    res.json(orders);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Get all orders (owner only)
app.get('/orders', authenticate, async (req, res) => {
  if (req.user.role !== 'owner') {
    return res.status(403).json({ error: 'Only owners can view all orders' });
  }

  try {
    const orders = await Order.find({ status: { $ne: 'draft' } }).populate('userId', 'email name').populate('deliveredBy').populate('items.productId');
    res.json(orders);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Confirm order and generate OTP (owner only)
app.patch('/orders/:orderId/confirm', authenticate, async (req, res) => {
  if (req.user.role !== 'owner') {
    return res.status(403).json({ error: 'Only owners can confirm orders' });
  }

  const { orderId } = req.params;
  try {
    const order = await Order.findById(orderId);
    if (!order) {
      return res.status(404).json({ error: 'Order not found' });
    }
    if (order.status !== 'pending') {
      return res.status(400).json({ error: 'Order is not pending' });
    }

    order.status = 'confirmed';
    order.otp = generateOTP();
    order.updatedAt = Date.now();
    await order.save();

    res.status(200).json({ message: 'Order confirmed successfully' });
  } catch (err) {
    console.error('Confirm order error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Track OTP attempts
app.post('/orders/otp/attempt', authenticate, async (req, res) => {
  if (req.user.role !== 'delivery') {
    return res.status(403).json({ error: 'Only delivery boys can attempt OTP' });
  }

  const { otp } = req.body;
  if (!otp) {
    return res.status(400).json({ error: 'OTP is required' });
  }

  try {
    let attempt = await OtpAttempts.findOne({ userId: req.user.userId });
    if (!attempt) {
      attempt = await OtpAttempts.create({ userId: req.user.userId, attempts: 0 });
    }

    // Check if last attempt was more than 30 seconds ago to reset attempts
    const now = new Date();
    const timeDiff = (now - attempt.lastAttempt) / 1000; // in seconds
    if (timeDiff > 30) {
      attempt.attempts = 0;
    }

    // Increment attempts
    attempt.attempts += 1;
    attempt.lastAttempt = now;

    if (attempt.attempts > 3) {
      // Handle lockout and potential permanent block
      if (!attempt.lastLockoutDate || attempt.lastLockoutDate.toDateString() !== now.toDateString()) {
        attempt.lockoutsToday = 1;
      } else {
        attempt.lockoutsToday += 1;
      }
      attempt.lastLockoutDate = now;

      if (attempt.lockoutsToday >= 2) {
        await User.findByIdAndUpdate(req.user.userId, { blocked: true });
        return res.status(403).json({ error: 'Account permanently blocked due to multiple failed OTP attempts today.' });
      }

      await attempt.save();
      return res.status(429).json({ error: 'Too many OTP attempts. Try again after 30 seconds.' });
    }

    await attempt.save();

    const order = await Order.findOne({ otp, status: 'confirmed' }).populate('userId', 'email name').populate('items.productId');
    if (!order) {
      return res.status(404).json({ error: 'No order found with this OTP or already delivered', attempts: attempt.attempts });
    }

    res.json({ order, attempts: attempt.attempts });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Search order by OTP (delivery only)
app.get('/orders/otp/:otp', authenticate, async (req, res) => {
  if (req.user.role !== 'delivery') {
    return res.status(403).json({ error: 'Only delivery boys can search by OTP' });
  }

  const { otp } = req.params;
  try {
    const order = await Order.findOne({ otp, status: 'confirmed' }).populate('userId', 'email name').populate('items.productId');
    if (!order) {
      return res.status(404).json({ error: 'No order found with this OTP or already delivered' });
    }
    res.json(order);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Mark order as delivered (delivery only)
app.patch('/orders/:orderId/deliver', authenticate, async (req, res) => {
  if (req.user.role !== 'delivery') {
    return res.status(403).json({ error: 'Only delivery boys can mark orders as delivered' });
  }

  const { orderId } = req.params;
  try {
    const order = await Order.findById(orderId);
    if (!order) {
      return res.status(404).json({ error: 'Order not found' });
    }
    if (order.status !== 'confirmed') {
      return res.status(400).json({ error: 'Order is not confirmed' });
    }

    order.status = 'delivered';
    order.deliveredBy = req.user.userId;
    order.updatedAt = Date.now();
    await order.save();

    res.json({ message: 'Order delivered successfully' });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Get delivery history (delivery only)
app.get('/orders/delivered', authenticate, async (req, res) => {
  if (req.user.role !== 'delivery') {
    return res.status(403).json({ error: 'Only delivery boys can view delivery history' });
  }

  try {
    const orders = await Order.find({ deliveredBy: req.user.userId }).populate('userId', 'email name').populate('items.productId');
    res.json(orders);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  } 
});

// Save user location
app.post('/user/location', authenticate, async (req, res) => {
  if (req.user.role !== 'user') return res.status(403).json({ error: 'Only users can save location' });
  const { lat, lng } = req.body;
  if (typeof lat !== 'number' || typeof lng !== 'number') {
    return res.status(400).json({ error: 'Invalid coordinates' });
  }
  try {
    await User.findByIdAndUpdate(req.user.userId, { location: { lat, lng } });
    res.json({ message: 'Location saved' });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Save selected point
app.post('/user/select-point', authenticate, async (req, res) => {
  if (req.user.role !== 'user') return res.status(403).json({ error: 'Only users can select point' });
  const { name, lat, lng } = req.body;
  if (!name || typeof lat !== 'number' || typeof lng !== 'number') {
    return res.status(400).json({ error: 'Invalid point data' });
  }
  try {
    await User.findByIdAndUpdate(req.user.userId, { selectedPoint: { name, lat, lng } });
    res.json({ message: 'Point selected' });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Get user location and selected point
app.get('/user/location', authenticate, async (req, res) => {
  if (req.user.role !== 'user') return res.status(403).json({ error: 'Only users can view location' });
  try {
    const user = await User.findById(req.user.userId).select('location selectedPoint');
    res.json({ location: user.location, selectedPoint: user.selectedPoint });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Get all points
app.get('/points', (req, res) => {
  res.json(POINTS);
});

// Start server 
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
