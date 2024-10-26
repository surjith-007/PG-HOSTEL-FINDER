/*
const express = require('express');
const mongoose = require('mongoose');
const path = require('path');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const crypto = require('crypto');
const fs = require('fs');
const port = 3019;

const app = express();

// Set the view engine to EJS
app.set('view engine', 'ejs');

// Middleware
app.use(express.static(__dirname));
app.use(express.urlencoded({ extended: true }));

// Ensure the upload directory exists
if (!fs.existsSync('uploads')) {
    fs.mkdirSync('uploads');
}

// MongoDB Connection
mongoose.connect('mongodb://127.0.0.1:27017/Customer').then(() => console.log('MongoDB connection successful'))
  .catch((error) => console.error('MongoDB connection error:', error));

// Encryption setup
const algorithm = 'aes-256-gcm';
const secretKey = crypto.randomBytes(32); 
const iv = crypto.randomBytes(16);

function encrypt(text) {
    const cipher = crypto.createCipheriv(algorithm, secretKey, iv);
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    const authTag = cipher.getAuthTag().toString('hex');
    return {
        iv: iv.toString('hex'),
        encryptedData: encrypted,
        authTag: authTag
    };
}

function decrypt(encryptedData, ivHex, authTagHex) {
    const decipher = crypto.createDecipheriv(algorithm, secretKey, Buffer.from(ivHex, 'hex'));
    decipher.setAuthTag(Buffer.from(authTagHex, 'hex'));
    let decrypted = decipher.update(encryptedData, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
}

// User Schema
const userSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true }
});

const User = mongoose.model('User', userSchema);

// Hostel Schema
const hostelSchema = new mongoose.Schema({
    name: { type: String, required: true },
    location: { type: String, required: true },
    rent: { type: Number, required: true },
    contactNumber: { type: String, required: true },
    description: String,
    image: String
});

const Hostel = mongoose.model('Hostel', hostelSchema, 'hostels');

// Payment Schema
const paymentSchema = new mongoose.Schema({
    hostelId: { type: mongoose.Schema.Types.ObjectId, ref: 'Hostel', required: true },
    userName: { type: String, required: true },
    contactNumber: { type: String, required: true },
    cardNumber: { type: String, required: true }, // Encrypted
    cardExpiry: { type: String, required: true }, // Encrypted
    cardCVV: { type: String, required: true }, // Encrypted
    iv: { type: String, required: true },
    authTag: { type: String, required: true },
    paymentDate: { type: Date, default: Date.now }
});

const Payment = mongoose.model('Payment', paymentSchema, 'payment');

// Multer storage configuration for image uploads
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, 'uploads/');
    },
    filename: function (req, file, cb) {
        cb(null, Date.now() + '-' + file.originalname);
    }
});

const upload = multer({ storage });

// Routes for authentication
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'login.html'));
});

app.get('/register', (req, res) => {
    res.sendFile(path.join(__dirname, 'register.html'));
});

app.get('/landing_page', (req, res) => {
    res.sendFile(path.join(__dirname, 'landing_page.html'));
});

app.get('/customersupport', (req, res) => {
    res.sendFile(path.join(__dirname, 'customersupport.html'));
});

// Handle registration
app.post('/register', async (req, res) => {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
        return res.redirect('/register?message=Missing+required+fields&type=error');
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const user = new User({ name, email, password: hashedPassword });
        await user.save();
        console.log('User registered:', user);
        res.redirect('/?message=Registration+successful&type=success');
    } catch (error) {
        if (error.code === 11000) {
            return res.redirect('/register?message=Email+already+exists&type=error');
        }
        console.error('Error registering user:', error);
        res.redirect('/register?message=Error+registering+user&type=error');
    }
});

// Handle login
app.post('/login', async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.redirect('/?message=Missing+email+or+password&type=error');
    }

    try {
        const user = await User.findOne({ email });
        if (!user) {
            return res.redirect('/?message=User+not+found&type=error');
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.redirect('/?message=Invalid+password&type=error');
        }

        console.log('User logged in:', user);
        res.redirect('/landing_page?message=Login+successful&type=success');
    } catch (error) {
        console.error('Error during login:', error);
        res.redirect('/?message=Error+during+login&type=error');
    }
});

// Hostel form route
app.get('/hostel_form', (req, res) => {
    res.sendFile(path.join(__dirname, 'hostel_form.html'));
});

// Handle hostel form submission
app.post('/submit_hostel', upload.single('hostelImage'), async (req, res) => {
    // Check if multer returned an error
    if (req.fileValidationError) {
        return res.redirect('/hostel_form?message=' + req.fileValidationError + '&type=error');
    }

    const { hostelName, hostelLocation, hostelRent, hostelContact, hostelDescription } = req.body;
    const hostelImage = req.file ? req.file.path : null;

    if (!hostelName || !hostelLocation || !hostelRent || !hostelContact || !hostelImage) {
        return res.redirect('/hostel_form?message=Missing+required+fields&type=error');
    }

    try {
        const hostel = new Hostel({
            name: hostelName,
            location: hostelLocation,
            rent: hostelRent,
            contactNumber: hostelContact,
            description: hostelDescription,
            image: hostelImage
        });
        await hostel.save();
        console.log('Hostel data saved:', hostel);
        res.redirect('/hostel_form?message=Hostel+data+successfully+submitted&type=success');
    } catch (error) {
        console.error('Error submitting hostel data:', error);
        res.redirect('/hostel_form?message=Error+submitting+hostel+data&type=error');
    }
});


// Display hostels
app.get('/hostels', async (req, res) => {
    try {
        const hostels = await Hostel.find({});
        res.render('hostels', { hostels });
    } catch (error) {
        console.error('Error fetching hostels:', error);
        res.status(500).send('Error fetching hostels');
    }
});

// Payment page route
app.get('/payment', async (req, res) => {
    const { hostelId } = req.query;

    try {
        const hostel = await Hostel.findById(hostelId);
        if (!hostel) return res.status(404).send('Hostel not found');
        res.render('payment', { hostel });
    } catch (error) {
        console.error('Error fetching hostel for payment:', error);
        res.status(500).send('Error fetching hostel for payment');
    }
});

// Process payment (with encryption)
app.post('/process_payment', async (req, res) => {
    const { hostelId, userName, contactNumber, cardNumber, cardExpiry, cardCVV } = req.body;

    try {
        const encryptedCardNumber = encrypt(cardNumber);
        const encryptedCardExpiry = encrypt(cardExpiry);
        const encryptedCardCVV = encrypt(cardCVV);

        const payment = new Payment({
            hostelId,
            userName,
            contactNumber,
            cardNumber: encryptedCardNumber.encryptedData,
            cardExpiry: encryptedCardExpiry.encryptedData,
            cardCVV: encryptedCardCVV.encryptedData,
            iv: encryptedCardNumber.iv, 
            authTag: encryptedCardNumber.authTag 
        });

        await payment.save();
        console.log('Payment saved successfully:', payment);
        res.redirect(`/payment_success?hostelId=${hostelId}&userName=${userName}`);
    } catch (error) {
        console.error('Error processing payment:', error);
        res.status(500).send('Error processing payment');
    }
});

// Payment success page
app.get('/payment_success', async (req, res) => {
    const { hostelId, userName } = req.query;

    try {
        const hostel = await Hostel.findById(hostelId);
        if (!hostel) return res.status(404).send('Hostel not found');
        res.render('payment_success', {
            userName,
            hostelName: hostel.name,
            hostelRent: hostel.rent
        });
    } catch (error) {
        console.error('Error fetching hostel for payment success:', error);
        res.status(500).send('Error fetching hostel for payment success');
    }
});

// Start the server
app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});

*/





/*const express = require('express');
const mongoose = require('mongoose');
const path = require('path');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const stripe = require('stripe')('sk_test_51QC0tUGURIQ2I0GsCixPdbXSyw3gpctKKV1jLcSK8WuaHw0tMu0fru2zjMncw62eXKuK8SeHG2L0bgpssW1weeav00oZwv4rj8'); // Replace with your actual Stripe Secret Key
const port = 3019;

const app = express(); // Initialize the app

// Set the view engine to EJS
app.set('view engine', 'ejs');

// Middleware
app.use(express.static(__dirname)); // Serve static files
app.use(express.urlencoded({ extended: true }));
app.use(express.json()); // To parse JSON bodies for Stripe webhooks

// MongoDB Connection
mongoose.connect('mongodb://127.0.0.1:27017/Customer', {})
  .then(() => console.log('MongoDB connection successful'))
  .catch((error) => console.error('MongoDB connection error:', error));

// User Schema
const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true }
});

const User = mongoose.model('User', userSchema);

// Hostel Schema
const hostelSchema = new mongoose.Schema({
  name: { type: String, required: true },
  location: { type: String, required: true },
  rent: { type: Number, required: true },
  contactNumber: { type: String, required: true },
  description: String,
  image: String
});

const Hostel = mongoose.model('Hostel', hostelSchema, 'hostels');

// Payment Schema
const paymentSchema = new mongoose.Schema({
  hostelId: { type: mongoose.Schema.Types.ObjectId, ref: 'Hostel', required: true },
  userName: { type: String, required: true },
  contactNumber: { type: String, required: true },
  stripePaymentId: { type: String, required: true }, // Stripe Payment ID
  paymentDate: { type: Date, default: Date.now }
});

const Payment = mongoose.model('Payment', paymentSchema, 'payment');

// Multer storage configuration for image uploads
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, 'uploads/');
  },
  filename: function (req, file, cb) {
    cb(null, Date.now() + '-' + file.originalname);
  }
});

const upload = multer({ storage });

// Routes for authentication
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'login.html'));
});

app.get('/register', (req, res) => {
  res.sendFile(path.join(__dirname, 'register.html'));
});

app.get('/landing_page', (req, res) => {
  res.sendFile(path.join(__dirname, 'landing_page.html'));
});

app.get('/customersupport', (req, res) => {
  res.sendFile(path.join(__dirname, 'customersupport.html'));
});

// Handle registration
app.post('/register', async (req, res) => {
  const { name, email, password } = req.body;

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ name, email, password: hashedPassword });
    await user.save();
    console.log('User registered:', user);
    res.redirect('/?message=Registration+successful&type=success');
  } catch (error) {
    console.error('Error registering user:', error);
    res.redirect('/register?message=Error+registering+user&type=error');
  }
});

// Handle login
app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.redirect('/?message=User+not+found&type=error');
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.redirect('/?message=Invalid+password&type=error');
    }

    console.log('User logged in:', user);
    res.redirect('/landing_page?message=Login+successful&type=success');
  } catch (error) {
    console.error('Error during login:', error);
    res.redirect('/?message=Error+during+login&type=error');
  }
});

// Hostel form route
app.get('/hostel_form', (req, res) => {
  res.sendFile(path.join(__dirname, 'hostel_form.html'));
});

// Handle hostel form submission
app.post('/submit_hostel', upload.single('hostelImage'), async (req, res) => {
  const { hostelName, hostelLocation, hostelRent, hostelContact, hostelDescription } = req.body;
  const hostelImage = req.file ? req.file.path : null;

  try {
    const hostel = new Hostel({
      name: hostelName,
      location: hostelLocation,
      rent: hostelRent,
      contactNumber: hostelContact,
      description: hostelDescription,
      image: hostelImage
    });
    await hostel.save();
    console.log('Hostel data saved:', hostel);
    res.redirect('/hostel_form?message=Hostel+data+successfully+submitted&type=success');
  } catch (error) {
    console.error('Error submitting hostel data:', error);
    res.redirect('/hostel_form?message=Error+submitting+hostel+data&type=error');
  }
});

// Display hostels
app.get('/hostels', async (req, res) => {
  try {
    const hostels = await Hostel.find({});
    res.render('hostels', { hostels });
  } catch (error) {
    console.error('Error fetching hostels:', error);
    res.status(500).send('Error fetching hostels');
  }
});

// Payment page route
app.get('/payment', async (req, res) => {
  const { hostelId } = req.query;

  try {
    const hostel = await Hostel.findById(hostelId);
    if (!hostel) return res.status(404).send('Hostel not found');
    res.render('payment', { hostel });
  } catch (error) {
    console.error('Error fetching hostel for payment:', error);
    res.status(500).send('Error fetching hostel for payment');
  }
});

// Stripe Payment
app.post('/create-checkout-session', async (req, res) => {
  const { hostelId, userName, contactNumber } = req.body;

  try {
    const hostel = await Hostel.findById(hostelId);
    if (!hostel) return res.status(404).send('Hostel not found');

    const session = await stripe.checkout.sessions.create({
      payment_method_types: ['card'],
      line_items: [{
        price_data: {
          currency: 'inr',
          product_data: {
            name: `Hostel Rent for ${hostel.name}`,
          },
          unit_amount: hostel.rent * 100, // Amount in paise
        },
        quantity: 1,
      }],
      mode: 'payment',
      success_url: `${req.headers.origin}/payment_success?hostelId=${hostelId}&userName=${userName}`,
      cancel_url: `${req.headers.origin}/payment?hostelId=${hostelId}&error=Payment+Cancelled`,
    });

    res.json({ id: session.id });
  } catch (error) {
    console.error('Error creating Stripe session:', error);
    res.status(500).send('Error creating Stripe session');
  }
});

// Payment success page
app.get('/payment_success', async (req, res) => {
  const { hostelId, userName } = req.query;

  try {
    const hostel = await Hostel.findById(hostelId);
    if (!hostel) return res.status(404).send('Hostel not found');
    res.render('payment_success', {
      userName,
      hostelName: hostel.name,
      hostelRent: hostel.rent
    });
  } catch (error) {
    console.error('Error fetching hostel for payment success:', error);
    res.status(500).send('Error fetching hostel for payment success');
  }
});

// Start the server
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});*/







/*
const express = require('express');
const mongoose = require('mongoose');
const path = require('path');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const crypto = require('crypto');
const fs = require('fs');
const session = require('express-session');
const port = 3019;

const app = express();

// Set the view engine to EJS
app.set('view engine', 'ejs');

// Middleware
app.use(express.static(__dirname));
app.use(express.urlencoded({ extended: true }));

// Ensure the upload directory exists
if (!fs.existsSync('uploads')) {
    fs.mkdirSync('uploads');
}

// MongoDB Connection
mongoose.connect('mongodb://127.0.0.1:27017/Customer')
    .then(() => console.log('MongoDB connection successful'))
    .catch((error) => console.error('MongoDB connection error:', error));

// Encryption setup
const algorithm = 'aes-256-gcm';
const secretKey = crypto.randomBytes(32);
const iv = crypto.randomBytes(16);

function encrypt(text) {
    const cipher = crypto.createCipheriv(algorithm, secretKey, iv);
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    const authTag = cipher.getAuthTag().toString('hex');
    return {
        iv: iv.toString('hex'),
        encryptedData: encrypted,
        authTag: authTag
    };
}

function decrypt(encryptedData, ivHex, authTagHex) {
    const decipher = crypto.createDecipheriv(algorithm, secretKey, Buffer.from(ivHex, 'hex'));
    decipher.setAuthTag(Buffer.from(authTagHex, 'hex'));
    let decrypted = decipher.update(encryptedData, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
}

// User Schema
const userSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    isAdmin: { type: Boolean, default: false }  // Admin flag
});

const User = mongoose.model('User', userSchema);

// Hostel Schema
const hostelSchema = new mongoose.Schema({
    name: { type: String, required: true },
    location: { type: String, required: true },
    rent: { type: Number, required: true },
    contactNumber: { type: String, required: true },
    description: String,
    image: String
});

const Hostel = mongoose.model('Hostel', hostelSchema, 'hostels');

// Payment Schema
const paymentSchema = new mongoose.Schema({
    hostelId: { type: mongoose.Schema.Types.ObjectId, ref: 'Hostel', required: true },
    userName: { type: String, required: true },
    contactNumber: { type: String, required: true },
    cardNumber: { type: String, required: true }, // Encrypted
    cardExpiry: { type: String, required: true }, // Encrypted
    cardCVV: { type: String, required: true }, // Encrypted
    iv: { type: String, required: true },
    authTag: { type: String, required: true },
    paymentDate: { type: Date, default: Date.now }
});

const Payment = mongoose.model('Payment', paymentSchema, 'payment');

// Multer storage configuration for image uploads
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, 'uploads/');
    },
    filename: function (req, file, cb) {
        cb(null, Date.now() + '-' + file.originalname);
    }
});

// Configure multer to accept only a single image
const upload = multer({ 
    storage,
    limits: { fileSize: 5 * 1024 * 1024 }, // Limit file size to 5 MB
    fileFilter: (req, file, cb) => {
        const filetypes = /jpeg|jpg|png|gif/; // Allow only image files
        const mimetype = filetypes.test(file.mimetype);
        const extname = filetypes.test(path.extname(file.originalname).toLowerCase());

        if (mimetype && extname) {
            return cb(null, true);
        }
        cb('Error: Only images are allowed!'); // Return an error for invalid file type
    }
}).single('hostelImage'); // Expect a single file with the field name 'hostelImage'

// Use session middleware
app.use(session({
    secret: 'your_secret_key',  // replace this with a strong secret key
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false }  // Set to true if using HTTPS
}));

// Middleware to set req.user if logged in
app.use((req, res, next) => {
    res.locals.user = req.session.user;  // make the user available in all views
    next();
});

// Middleware to check if the user is an admin
function isAdmin(req, res, next) {
    if (req.session.user && req.session.user.isAdmin) {
        return next();
    } else {
        res.redirect('/?message=Access+denied&type=error');
    }
}

// Routes for authentication
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'login.html'));
});

app.get('/register', (req, res) => {
    res.sendFile(path.join(__dirname, 'register.html'));
});

app.get('/landing_page', (req, res) => {
    res.sendFile(path.join(__dirname, 'landing_page.html'));
});

app.get('/customersupport', (req, res) => {
    res.sendFile(path.join(__dirname, 'customersupport.html'));
});

// Handle registration
app.post('/register', async (req, res) => {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
        return res.redirect('/register?message=Missing+required+fields&type=error');
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const user = new User({ name, email, password: hashedPassword });
        await user.save();
        console.log('User registered:', user);
        res.redirect('/?message=Registration+successful&type=success');
    } catch (error) {
        if (error.code === 11000) {
            return res.redirect('/register?message=Email+already+exists&type=error');
        }
        console.error('Error registering user:', error);
        res.redirect('/register?message=Error+registering+user&type=error');
    }
});

// Handle login
app.post('/login', async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.redirect('/?message=Missing+email+or+password&type=error');
    }

    try {
        const user = await User.findOne({ email });
        if (!user) {
            return res.redirect('/?message=User+not+found&type=error');
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.redirect('/?message=Invalid+password&type=error');
        }

        // Save user in session
        req.session.user = user;

        console.log('User logged in:', user);
        res.redirect('/landing_page?message=Login+successful&type=success');
    } catch (error) {
        console.error('Error during login:', error);
        res.redirect('/?message=Error+during+login&type=error');
    }
});

// Hostel form route
app.get('/hostel_form', (req, res) => {
    res.sendFile(path.join(__dirname, 'hostel_form.html'));
});

// Handle hostel form submission
app.post('/submit_hostel', upload, async (req, res) => {
    const { hostelName, hostelLocation, hostelRent, hostelContact, hostelDescription } = req.body;
    const hostelImage = req.file ? req.file.path : null;

    if (!hostelName || !hostelLocation || !hostelRent || !hostelContact || !hostelImage) {
        return res.redirect('/hostel_form?message=Missing+required+fields&type=error');
    }

    try {
        const hostel = new Hostel({
            name: hostelName,
            location: hostelLocation,
            rent: hostelRent,
            contactNumber: hostelContact,
            description: hostelDescription,
            image: hostelImage
        });
        await hostel.save();
        console.log('Hostel data saved:', hostel);
        res.redirect('/hostel_form?message=Hostel+data+successfully+submitted&type=success');
    } catch (error) {
        console.error('Error submitting hostel data:', error);
        res.redirect('/hostel_form?message=Error+submitting+hostel+data&type=error');
    }
});

// Display hostels
app.get('/hostels', async (req, res) => {
    try {
        const hostels = await Hostel.find({});
        res.render('hostel', { hostels });
    } catch (error) {
        console.error('Error fetching hostels:', error);
        res.status(500).send('Error fetching hostels');
    }
});

// Admin dashboard for hostels
app.get('/admin/hostels', isAdmin, async (req, res) => {
    try {
        const hostels = await Hostel.find({});
        res.render('admin_hostels', { hostels });
    } catch (error) {
        console.error('Error fetching hostels for admin:', error);
        res.status(500).send('Error fetching hostels for admin');
    }
});

// Payment processing route
app.get('/payment/:hostelId', async (req, res) => {
    const { hostelId } = req.params;

    try {
        const hostel = await Hostel.findById(hostelId);
        res.render('payment', { hostel });
    } catch (error) {
        console.error('Error fetching hostel for payment:', error);
        res.status(500).send('Error fetching hostel for payment');
    }
});

app.post('/process_payment', async (req, res) => {
    const { hostelId, userName, contactNumber, cardNumber, cardExpiry, cardCVV } = req.body;

    if (!hostelId || !userName || !contactNumber || !cardNumber || !cardExpiry || !cardCVV) {
        return res.redirect(`/payment/${hostelId}?message=Missing+required+fields&type=error`);
    }

    try {
        const encryptedCardNumber = encrypt(cardNumber);
        const encryptedCardExpiry = encrypt(cardExpiry);
        const encryptedCardCVV = encrypt(cardCVV);

        const payment = new Payment({
            hostelId,
            userName,
            contactNumber,
            cardNumber: encryptedCardNumber.encryptedData,
            cardExpiry: encryptedCardExpiry.encryptedData,
            cardCVV: encryptedCardCVV.encryptedData,
            iv: encryptedCardNumber.iv,
            authTag: encryptedCardNumber.authTag
        });
        
        await payment.save();
        console.log('Payment processed:', payment);
        res.redirect(`/hostels?message=Payment+successful&type=success`);
    } catch (error) {
        console.error('Error processing payment:', error);
        res.redirect(`/payment/${hostelId}?message=Error+processing+payment&type=error`);
    }
});

// Logout route
app.get('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            console.error('Error during logout:', err);
            return res.redirect('/?message=Error+during+logout&type=error');
        }
        res.redirect('/?message=Logged+out+successfully&type=success');
    });
});

// Start the server
app.listen(port, () => {
    console.log(`Server is running on http://localhost:${port}`);
});
*/






/*

const express = require('express'); 
const mongoose = require('mongoose');
const path = require('path');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const crypto = require('crypto');
const fs = require('fs');
const session = require('express-session');
const port = 3019;

const app = express();

// Set the view engine to EJS
app.set('view engine', 'ejs');

// Middleware
app.use(express.static(__dirname));
app.use(express.urlencoded({ extended: true }));

// Initialize session
app.use(session({
    secret: 'your_secret_key', // Change this to a secure random string
    resave: false,
    saveUninitialized: true,
}));

// Ensure the upload directory exists
if (!fs.existsSync('uploads')) {
    fs.mkdirSync('uploads');
}

// MongoDB Connection
mongoose.connect('mongodb://127.0.0.1:27017/Customer').then(() => console.log('MongoDB connection successful'))
    .catch((error) => console.error('MongoDB connection error:', error));

// Encryption setup
const algorithm = 'aes-256-gcm';
const secretKey = crypto.randomBytes(32);
const iv = crypto.randomBytes(16);

function encrypt(text) {
    const cipher = crypto.createCipheriv(algorithm, secretKey, iv);
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    const authTag = cipher.getAuthTag().toString('hex');
    return {
        iv: iv.toString('hex'),
        encryptedData: encrypted,
        authTag: authTag
    };
}

function decrypt(encryptedData, ivHex, authTagHex) {
    const decipher = crypto.createDecipheriv(algorithm, secretKey, Buffer.from(ivHex, 'hex'));
    decipher.setAuthTag(Buffer.from(authTagHex, 'hex'));
    let decrypted = decipher.update(encryptedData, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
}

// User Schema
const userSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    isAdmin: { type: Boolean, default: false } // Added isAdmin field
});

const User = mongoose.model('User', userSchema);

// Hostel Schema
const hostelSchema = new mongoose.Schema({
    name: { type: String, required: true },
    location: { type: String, required: true },
    rent: { type: Number, required: true },
    contactNumber: { type: String, required: true },
    description: String,
    image: String
});

const Hostel = mongoose.model('Hostel', hostelSchema, 'hostels');

// Payment Schema
const paymentSchema = new mongoose.Schema({
    hostelId: { type: mongoose.Schema.Types.ObjectId, ref: 'Hostel', required: true },
    userName: { type: String, required: true },
    contactNumber: { type: String, required: true },
    cardNumber: { type: String, required: true }, // Encrypted
    cardExpiry: { type: String, required: true }, // Encrypted
    cardCVV: { type: String, required: true }, // Encrypted
    iv: { type: String, required: true },
    authTag: { type: String, required: true },
    paymentDate: { type: Date, default: Date.now }
});

const Payment = mongoose.model('Payment', paymentSchema, 'payment');

// Multer storage configuration for image uploads
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, 'uploads/');
    },
    filename: function (req, file, cb) {
        cb(null, Date.now() + '-' + file.originalname);
    }
});

const upload = multer({ storage });

// Middleware to check if user is an admin
function isAdmin(req, res, next) {
    if (req.session.user && req.session.user.isAdmin) {
        return next();
    }
    res.redirect('/?message=Access+denied&type=error');
}

// Routes for authentication
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'login.html'));
});

app.get('/register', (req, res) => {
    res.sendFile(path.join(__dirname, 'register.html'));
});

app.get('/landing_page', (req, res) => {
    res.sendFile(path.join(__dirname, 'landing_page.html'));
});

app.get('/customersupport', (req, res) => {
    res.sendFile(path.join(__dirname, 'customersupport.html'));
});

// Handle registration
app.post('/register', async (req, res) => {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
        return res.redirect('/register?message=Missing+required+fields&type=error');
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const user = new User({ name, email, password: hashedPassword });
        await user.save();
        console.log('User registered:', user);
        res.redirect('/?message=Registration+successful&type=success');
    } catch (error) {
        if (error.code === 11000) {
            return res.redirect('/register?message=Email+already+exists&type=error');
        }
        console.error('Error registering user:', error);
        res.redirect('/register?message=Error+registering+user&type=error');
    }
});

// Handle login
app.post('/login', async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.redirect('/?message=Missing+email+or+password&type=error');
    }

    try {
        const user = await User.findOne({ email });
        if (!user) {
            return res.redirect('/?message=User+not+found&type=error');
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.redirect('/?message=Invalid+password&type=error');
        }

        // Store user information in session
        req.session.user = { id: user._id, name: user.name, isAdmin: user.isAdmin };
        console.log('User logged in:', user);
        res.redirect('/landing_page?message=Login+successful&type=success');
    } catch (error) {
        console.error('Error during login:', error);
        res.redirect('/?message=Error+during+login&type=error');
    }
});

// Hostel form route
app.get('/hostel_form', (req, res) => {
    res.sendFile(path.join(__dirname, 'hostel_form.html'));
});

// Handle hostel form submission
app.post('/submit_hostel', upload.single('hostelImage'), async (req, res) => {
    // Check if multer returned an error
    if (req.fileValidationError) {
        return res.redirect('/hostel_form?message=' + req.fileValidationError + '&type=error');
    }

    const { hostelName, hostelLocation, hostelRent, hostelContact, hostelDescription } = req.body;
    const hostelImage = req.file ? req.file.path : null;

    if (!hostelName || !hostelLocation || !hostelRent || !hostelContact || !hostelImage) {
        return res.redirect('/hostel_form?message=Missing+required+fields&type=error');
    }

    try {
        const hostel = new Hostel({
            name: hostelName,
            location: hostelLocation,
            rent: hostelRent,
            contactNumber: hostelContact,
            description: hostelDescription,
            image: hostelImage
        });
        await hostel.save();
        console.log('Hostel data saved:', hostel);
        res.redirect('/hostel_form?message=Hostel+data+successfully+submitted&type=success');
    } catch (error) {
        console.error('Error submitting hostel data:', error);
        res.redirect('/hostel_form?message=Error+submitting+hostel+data&type=error');
    }
});

// Display hostels
app.get('/hostels', async (req, res) => {
    try {
        const hostels = await Hostel.find({});
        res.render('hostels', { hostels });
    } catch (error) {
        console.error('Error fetching hostels:', error);
        res.status(500).send('Error fetching hostels');
    }
});

// Payment page route
app.get('/payment', async (req, res) => {
    const { hostelId } = req.query;

    try {
        const hostel = await Hostel.findById(hostelId);
        if (!hostel) return res.status(404).send('Hostel not found');
        res.render('payment', { hostel });
    } catch (error) {
        console.error('Error fetching hostel for payment:', error);
        res.status(500).send('Error fetching hostel for payment');
    }
});

// Process payment (with encryption)
app.post('/process_payment', async (req, res) => {
    const { hostelId, userName, contactNumber, cardNumber, cardExpiry, cardCVV } = req.body;

    const encryptedCard = encrypt(cardNumber);
    const encryptedExpiry = encrypt(cardExpiry);
    const encryptedCVV = encrypt(cardCVV);

    const payment = new Payment({
        hostelId,
        userName,
        contactNumber,
        cardNumber: encryptedCard.encryptedData,
        cardExpiry: encryptedExpiry.encryptedData,
        cardCVV: encryptedCVV.encryptedData,
        iv: encryptedCard.iv,
        authTag: encryptedCard.authTag
    });

    try {
        await payment.save();
        console.log('Payment processed:', payment);
        res.redirect('/hostels?message=Payment+successful&type=success');
    } catch (error) {
        console.error('Error processing payment:', error);
        res.redirect('/payment?message=Error+processing+payment&type=error');
    }
});

// Admin Dashboard
app.get('/admin_dashboard', isAdmin, (req, res) => {
    res.render('admin_dashboard', { user: req.session.user });
});

// Admin Hostels Management
app.get('/admin_hostels', isAdmin, async (req, res) => {
    try {
        const hostels = await Hostel.find({});
        res.render('admin_hostels', { hostels });
    } catch (error) {
        console.error('Error fetching hostels for admin:', error);
        res.status(500).send('Error fetching hostels');
    }
});

// Admin New Hostel Form
app.get('/admin_new_hostel', isAdmin, (req, res) => {
    res.render('admin_new_hostel');
});

// Admin Users Management
app.get('/admin/users', isAdmin, async (req, res) => {
    try {
        const users = await User.find({});
        res.render('users', { users });
    } catch (error) {
        console.error('Error fetching users:', error);
        res.status(500).send('Error fetching users');
    }
});

// Start the server
app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});
*/




/*
const express = require('express'); 
const mongoose = require('mongoose');
const path = require('path');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const crypto = require('crypto');
const fs = require('fs');
const session = require('express-session');
const port = 3019;

const app = express();

// Set the view engine to EJS
app.set('view engine', 'ejs');

// Middleware
app.use(express.static(__dirname));
app.use(express.urlencoded({ extended: true }));

// Initialize session
app.use(session({
    secret: 'your_secret_key', // Change this to a secure random string
    resave: false,
    saveUninitialized: true,
}));

// Ensure the upload directory exists
if (!fs.existsSync('uploads')) {
    fs.mkdirSync('uploads');
}

// MongoDB Connection
mongoose.connect('mongodb://127.0.0.1:27017/Customer').then(() => console.log('MongoDB connection successful'))
    .catch((error) => console.error('MongoDB connection error:', error));

// Encryption setup
const algorithm = 'aes-256-gcm';
const secretKey = crypto.randomBytes(32);
const iv = crypto.randomBytes(16);

function encrypt(text) {
    const cipher = crypto.createCipheriv(algorithm, secretKey, iv);
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    const authTag = cipher.getAuthTag().toString('hex');
    return {
        iv: iv.toString('hex'),
        encryptedData: encrypted,
        authTag: authTag
    };
}

function decrypt(encryptedData, ivHex, authTagHex) {
    const decipher = crypto.createDecipheriv(algorithm, secretKey, Buffer.from(ivHex, 'hex'));
    decipher.setAuthTag(Buffer.from(authTagHex, 'hex'));
    let decrypted = decipher.update(encryptedData, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
}

// User Schema
const userSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    isAdmin: { type: Boolean, default: false } // Added isAdmin field
});

const User = mongoose.model('User', userSchema);

// Hostel Schema
const hostelSchema = new mongoose.Schema({
    name: { type: String, required: true },
    location: { type: String, required: true },
    rent: { type: Number, required: true },
    contactNumber: { type: String, required: true },
    description: String,
    image: String
});

const Hostel = mongoose.model('Hostel', hostelSchema, 'hostels');

// Payment Schema
const paymentSchema = new mongoose.Schema({
    hostelId: { type: mongoose.Schema.Types.ObjectId, ref: 'Hostel', required: true },
    userName: { type: String, required: true },
    contactNumber: { type: String, required: true },
    cardNumber: { type: String, required: true }, // Encrypted
    cardExpiry: { type: String, required: true }, // Encrypted
    cardCVV: { type: String, required: true }, // Encrypted
    iv: { type: String, required: true },
    authTag: { type: String, required: true },
    paymentDate: { type: Date, default: Date.now }
});

const Payment = mongoose.model('Payment', paymentSchema, 'payment');

// Multer storage configuration for image uploads
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, 'uploads/');
    },
    filename: function (req, file, cb) {
        cb(null, Date.now() + '-' + file.originalname);
    }
});

const upload = multer({ storage });

// Middleware to check if user is an admin
function isAdmin(req, res, next) {
    if (req.session.user && req.session.user.isAdmin) {
        return next();
    }
    res.redirect('/?message=Access+denied&type=error');
}

// Routes for authentication
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'login.html'));
});

app.get('/register', (req, res) => {
    res.sendFile(path.join(__dirname, 'register.html'));
});

app.get('/landing_page', (req, res) => {
    res.sendFile(path.join(__dirname, 'landing_page.html'));
});

app.get('/customersupport', (req, res) => {
    res.sendFile(path.join(__dirname, 'customersupport.html'));
});

// Handle registration
app.post('/register', async (req, res) => {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
        return res.redirect('/register?message=Missing+required+fields&type=error');
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const user = new User({ name, email, password: hashedPassword });
        await user.save();
        console.log('User registered:', user);
        res.redirect('/?message=Registration+successful&type=success');
    } catch (error) {
        if (error.code === 11000) {
            return res.redirect('/register?message=Email+already+exists&type=error');
        }
        console.error('Error registering user:', error);
        res.redirect('/register?message=Error+registering+user&type=error');
    }
});

// Handle login
app.post('/login', async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.redirect('/?message=Missing+email+or+password&type=error');
    }

    try {
        const user = await User.findOne({ email });
        if (!user) {
            return res.redirect('/?message=User+not+found&type=error');
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.redirect('/?message=Invalid+password&type=error');
        }

        // Store user information in session
        req.session.user = { id: user._id, name: user.name, isAdmin: user.isAdmin };
        console.log('User logged in:', user); // Log the logged-in user

        // Redirect based on whether the user is an admin
        if (user.isAdmin) {
            return res.redirect('/admin_dashboard'); // Redirect to admin dashboard
        }

        // Redirect to regular landing page for non-admin users
        res.redirect('/landing_page?message=Login+successful&type=success');
    } catch (error) {
        console.error('Error during login:', error);
        res.redirect('/?message=Error+during+login&type=error');
    }
});

// Hostel form route
app.get('/hostel_form', (req, res) => {
    res.sendFile(path.join(__dirname, 'hostel_form.html'));
});

// Handle hostel form submission
app.post('/submit_hostel', upload.single('hostelImage'), async (req, res) => {
    // Check if multer returned an error
    if (req.fileValidationError) {
        return res.redirect('/hostel_form?message=' + req.fileValidationError + '&type=error');
    }

    const { hostelName, hostelLocation, hostelRent, hostelContact, hostelDescription } = req.body;
    const hostelImage = req.file ? req.file.path : null;

    if (!hostelName || !hostelLocation || !hostelRent || !hostelContact || !hostelImage) {
        return res.redirect('/hostel_form?message=Missing+required+fields&type=error');
    }

    try {
        const hostel = new Hostel({
            name: hostelName,
            location: hostelLocation,
            rent: hostelRent,
            contactNumber: hostelContact,
            description: hostelDescription,
            image: hostelImage
        });
        await hostel.save();
        console.log('Hostel data saved:', hostel);
        res.redirect('/hostel_form?message=Hostel+data+successfully+submitted&type=success');
    } catch (error) {
        console.error('Error submitting hostel data:', error);
        res.redirect('/hostel_form?message=Error+submitting+hostel+data&type=error');
    }
});

// Display hostels
app.get('/hostels', async (req, res) => {
    try {
        const hostels = await Hostel.find({});
        res.render('hostels', { hostels });
    } catch (error) {
        console.error('Error fetching hostels:', error);
        res.status(500).send('Error fetching hostels');
    }
});

// Payment page route
app.get('/payment', async (req, res) => {
    const { hostelId } = req.query;

    try {
        const hostel = await Hostel.findById(hostelId);
        if (!hostel) return res.status(404).send('Hostel not found');
        res.render('payment', { hostel });
    } catch (error) {
        console.error('Error fetching hostel for payment:', error);
        res.status(500).send('Error fetching hostel for payment');
    }
});

// Process payment (with encryption)
app.post('/process_payment', async (req, res) => {
    const { hostelId, userName, contactNumber, cardNumber, cardExpiry, cardCVV } = req.body;

    const encryptedCardNumber = encrypt(cardNumber);
    const encryptedCardExpiry = encrypt(cardExpiry);
    const encryptedCardCVV = encrypt(cardCVV);

    const payment = new Payment({
        hostelId,
        userName,
        contactNumber,
        cardNumber: encryptedCardNumber.encryptedData,
        cardExpiry: encryptedCardExpiry.encryptedData,
        cardCVV: encryptedCardCVV.encryptedData,
        iv: encryptedCardNumber.iv,
        authTag: encryptedCardNumber.authTag,
    });

    try {
        await payment.save();
        console.log('Payment processed:', payment);
        res.redirect('/?message=Payment+successful&type=success');
    } catch (error) {
        console.error('Error processing payment:', error);
        res.redirect('/payment?hostelId=' + hostelId + '&message=Error+processing+payment&type=error');
    }
});


// Admin Dashboard
app.get('/admin_dashboard', isAdmin, async (req, res) => {
    try {
        const hostels = await Hostel.find({});
        res.render('admin_dashboard', { user: req.session.user, hostels }); // Pass hostels to the view
    } catch (error) {
        console.error('Error fetching hostels for admin dashboard:', error);
        res.status(500).send('Error fetching hostels for admin dashboard');
    }
});


// Start the server
app.listen(port, () => {
    console.log(`Server is running on http://localhost:${port}`);
});
*/

/*
const express = require('express'); 
const mongoose = require('mongoose');
const path = require('path');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const crypto = require('crypto');
const fs = require('fs');
const session = require('express-session');
const port = 3019;

const app = express();

// Set the view engine to EJS
app.set('view engine', 'ejs');

// Middleware
app.use(express.static(__dirname));
app.use(express.urlencoded({ extended: true }));

// Initialize session
app.use(session({
    secret: 'your_secret_key', // Change this to a secure random string
    resave: false,
    saveUninitialized: true,
}));

// Ensure the upload directory exists
if (!fs.existsSync('uploads')) {
    fs.mkdirSync('uploads');
}

// MongoDB Connection
mongoose.connect('mongodb://127.0.0.1:27017/Customer').then(() => console.log('MongoDB connection successful'))
    .catch((error) => console.error('MongoDB connection error:', error));

// Encryption setup
const algorithm = 'aes-256-gcm';
const secretKey = crypto.randomBytes(32);
const iv = crypto.randomBytes(16);

function encrypt(text) {
    const cipher = crypto.createCipheriv(algorithm, secretKey, iv);
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    const authTag = cipher.getAuthTag().toString('hex');
    return {
        iv: iv.toString('hex'),
        encryptedData: encrypted,
        authTag: authTag
    };
}

// Decrypt function (optional if needed for admin review)
function decrypt(encryptedData, ivHex, authTagHex) {
    const decipher = crypto.createDecipheriv(algorithm, secretKey, Buffer.from(ivHex, 'hex'));
    decipher.setAuthTag(Buffer.from(authTagHex, 'hex'));
    let decrypted = decipher.update(encryptedData, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
}

// User Schema
const userSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    isAdmin: { type: Boolean, default: false } // Added isAdmin field
});

const User = mongoose.model('User', userSchema);

// Hostel Schema
const hostelSchema = new mongoose.Schema({
    name: { type: String, required: true },
    location: { type: String, required: true },
    rent: { type: Number, required: true },
    contactNumber: { type: String, required: true },
    description: String,
    image: String
});

const Hostel = mongoose.model('Hostel', hostelSchema, 'hostels');

// Payment Schema
const paymentSchema = new mongoose.Schema({
    hostelId: { type: mongoose.Schema.Types.ObjectId, ref: 'Hostel', required: true },
    userName: { type: String, required: true },
    contactNumber: { type: String, required: true },
    cardNumber: { type: String, required: true }, // Encrypted
    cardExpiry: { type: String, required: true }, // Encrypted
    cardCVV: { type: String, required: true }, // Encrypted
    iv: { type: String, required: true },
    authTag: { type: String, required: true },
    paymentDate: { type: Date, default: Date.now }
});

const Payment = mongoose.model('Payment', paymentSchema, 'payment');

// Multer storage configuration for image uploads
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, 'uploads/');
    },
    filename: function (req, file, cb) {
        cb(null, Date.now() + '-' + file.originalname);
    }
});

const upload = multer({ storage });

// Middleware to check if user is an admin
function isAdmin(req, res, next) {
    if (req.session.user && req.session.user.isAdmin) {
        return next();
    }
    res.redirect('/?message=Access+denied&type=error');
}

// Routes for authentication
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'login.html'));
});

app.get('/register', (req, res) => {
    res.sendFile(path.join(__dirname, 'register.html'));
});

app.get('/landing_page', (req, res) => {
    res.sendFile(path.join(__dirname, 'landing_page.html'));
});

app.get('/customersupport', (req, res) => {
    res.sendFile(path.join(__dirname, 'customersupport.html'));
});

// Handle registration
app.post('/register', async (req, res) => {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
        return res.redirect('/register?message=Missing+required+fields&type=error');
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const user = new User({ name, email, password: hashedPassword });
        await user.save();
        console.log('User registered:', user);
        res.redirect('/?message=Registration+successful&type=success');
    } catch (error) {
        if (error.code === 11000) {
            return res.redirect('/register?message=Email+already+exists&type=error');
        }
        console.error('Error registering user:', error);
        res.redirect('/register?message=Error+registering+user&type=error');
    }
});

// Handle login
app.post('/login', async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.redirect('/?message=Missing+email+or+password&type=error');
    }

    try {
        const user = await User.findOne({ email });
        if (!user) {
            return res.redirect('/?message=User+not+found&type=error');
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.redirect('/?message=Invalid+password&type=error');
        }

        // Store user information in session
        req.session.user = { id: user._id, name: user.name, isAdmin: user.isAdmin };
        console.log('User logged in:', user); // Log the logged-in user

        // Redirect based on whether the user is an admin
        if (user.isAdmin) {
            return res.redirect('/admin_dashboard'); // Redirect to admin dashboard
        }

        // Redirect to regular landing page for non-admin users
        res.redirect('/landing_page?message=Login+successful&type=success');
    } catch (error) {
        console.error('Error during login:', error);
        res.redirect('/?message=Error+during+login&type=error');
    }
});



//admin hostel delete
app.post('/admin/hostels/delete/:id', isAdmin, async (req, res) => {
    try {
        await Hostel.findByIdAndDelete(req.params.id);
        res.redirect('/admin_hostels?message=Hostel+successfully+deleted&type=success');
    } catch (error) {
        console.error('Error deleting hostel:', error);
        res.status(500).send('Error deleting hostel');
    }
});

//admin hostel edit
app.get('/admin/hostels/edit/:id', isAdmin, async (req, res) => {
    try {
        const hostel = await Hostel.findById(req.params.id);
        if (!hostel) {
            return res.status(404).send('Hostel not found');
        }
        res.render('admin_edit_hostel', { hostel });
    } catch (error) {
        console.error('Error fetching hostel:', error);
        res.status(500).send('Error fetching hostel');
    }
});


// Hostel form route
app.get('/hostel_form', (req, res) => {
    res.sendFile(path.join(__dirname, 'hostel_form.html'));
});

// Handle hostel form submission
app.post('/submit_hostel', upload.single('hostelImage'), async (req, res) => {
    const { hostelName, hostelLocation, hostelRent, hostelContact, hostelDescription } = req.body;
    const hostelImage = req.file ? req.file.path : null;

    if (!hostelName || !hostelLocation || !hostelRent || !hostelContact || !hostelImage) {
        return res.redirect('/hostel_form?message=Missing+required+fields&type=error');
    }

    try {
        const hostel = new Hostel({
            name: hostelName,
            location: hostelLocation,
            rent: hostelRent,
            contactNumber: hostelContact,
            description: hostelDescription,
            image: hostelImage
        });
        await hostel.save();
        console.log('Hostel data saved:', hostel);
        res.redirect('/hostel_form?message=Hostel+data+successfully+submitted&type=success');
    } catch (error) {
        console.error('Error submitting hostel data:', error);
        res.redirect('/hostel_form?message=Error+submitting+hostel+data&type=error');
    }
});


app.post('/admin/hostels/edit/:id', isAdmin, upload.single('hostelImage'), async (req, res) => {
    const { hostelName, hostelLocation, hostelRent, hostelContact, hostelDescription } = req.body;
    const hostelImage = req.file ? req.file.path : req.body.currentImage;  // Check if a new image was uploaded

    try {
        await Hostel.findByIdAndUpdate(req.params.id, {
            name: hostelName,
            location: hostelLocation,
            rent: hostelRent,
            contactNumber: hostelContact,
            description: hostelDescription,
            image: hostelImage
        });
        res.redirect('/admin_hostels?message=Hostel+successfully+updated&type=success');
    } catch (error) {
        console.error('Error updating hostel:', error);
        res.status(500).send('Error updating hostel');
    }
});


app.post('/admin/hostels/new', isAdmin, upload.single('hostelImage'), async (req, res) => {
    const { hostelName, hostelLocation, hostelRent, hostelContact, hostelDescription } = req.body;
    const hostelImage = req.file ? req.file.path : null;

    if (!hostelName || !hostelLocation || !hostelRent || !hostelContact || !hostelImage) {
        return res.redirect('/admin/hostels/new?message=Missing+required+fields&type=error');
    }

    try {
        const hostel = new Hostel({
            name: hostelName,
            location: hostelLocation,
            rent: hostelRent,
            contactNumber: hostelContact,
            description: hostelDescription,
            image: hostelImage
        });
        await hostel.save();
        res.redirect('/admin_hostels?message=Hostel+added+successfully&type=success');
    } catch (error) {
        console.error('Error adding hostel:', error);
        res.status(500).send('Error adding hostel');
    }
});


// Display hostels
app.get('/hostels', async (req, res) => {
    try {
        const hostels = await Hostel.find({});
        res.render('hostels', { hostels });
    } catch (error) {
        console.error('Error fetching hostels:', error);
        res.status(500).send('Error fetching hostels');
    }
});

app.get('/admin_dashboard', isAdmin, async (req, res) => {
    try {
        const users = await User.find({});
        const hostels = await Hostel.find({});
        res.render('admin_dashboard', { user: req.session.user, users, hostels }); // Pass the user object here
    } catch (error) {
        console.error('Error fetching admin data:', error);
        res.status(500).send('Error fetching admin data');
    }
});


// Payment page route
app.get('/payment', async (req, res) => {
    const { hostelId } = req.query;

    try {
        const hostel = await Hostel.findById(hostelId);
        if (!hostel) return res.status(404).send('Hostel not found');
        res.render('payment', { hostel });
    } catch (error) {
        console.error('Error fetching hostel for payment:', error);
        res.status(500).send('Error fetching hostel for payment');
    }
});

// Process payment (with encryption)
app.post('/process_payment', async (req, res) => {
    const { hostelId, userName, contactNumber, cardNumber, cardExpiry, cardCVV } = req.body;

    try {
        const encryptedCardNumber = encrypt(cardNumber);
        const encryptedCardExpiry = encrypt(cardExpiry);
        const encryptedCardCVV = encrypt(cardCVV);

        const payment = new Payment({
            hostelId,
            userName,
            contactNumber,
            cardNumber: encryptedCardNumber.encryptedData,
            cardExpiry: encryptedCardExpiry.encryptedData,
            cardCVV: encryptedCardCVV.encryptedData,
            iv: encryptedCardNumber.iv, 
            authTag: encryptedCardNumber.authTag 
        });

        await payment.save();
        console.log('Payment saved successfully:', payment);
        res.redirect(`/payment_success?hostelId=${hostelId}&userName=${userName}`);
    } catch (error) {
        console.error('Error processing payment:', error);
        res.status(500).send('Error processing payment');
    }
});

// Payment success page
app.get('/payment_success', async (req, res) => {
    const { hostelId, userName } = req.query;

    try {
        const hostel = await Hostel.findById(hostelId);
        if (!hostel) return res.status(404).send('Hostel not found');
        res.render('payment_success', {
            userName,
            hostelName: hostel.name,
            hostelRent: hostel.rent
        });
    } catch (error) {
        console.error('Error fetching hostel for payment success:', error);
        res.status(500).send('Error fetching hostel for payment success');
    }
});


// Admin manage hostels
app.get('/admin_hostels', isAdmin, async (req, res) => {
    try {
        const hostels = await Hostel.find({});
        res.render('admin_hostels', { hostels });
    } catch (error) {
        console.error('Error fetching hostels:', error);
        res.status(500).send('Error fetching hostels');
    }
});

// Admin add new hostel
app.get('/admin_new_hostel', isAdmin, (req, res) => {
    res.render('admin_new_hostel');
});

// Admin edit hostel
app.get('/admin_edit_hostel/:id', isAdmin, async (req, res) => {
    try {
        const hostel = await Hostel.findById(req.params.id);
        if (!hostel) {
            return res.status(404).send('Hostel not found');
        }
        res.render('admin_edit_hostel', { hostel });
    } catch (error) {
        console.error('Error fetching hostel:', error);
        res.status(500).send('Error fetching hostel');
    }
});

//admin add hostel
app.get('/admin/hostels/new', isAdmin, (req, res) => {
    res.render('admin_new_hostel');
});

//admin view user
app.get('/admin/users', isAdmin, async (req, res) => {
    try {
        const users = await User.find({});
        res.render('admin_users', { users });
    } catch (error) {
        console.error('Error fetching users:', error);
        res.status(500).send('Error fetching users');
    }
});

// Logout route
app.get('/logout', (req, res) => {
    // Destroy the session
    req.session.destroy((err) => {
        if (err) {
            console.error('Error logging out:', err);
            return res.redirect('/?message=Error+logging+out&type=error');
        }

        // Redirect to the login page after successful logout
        res.redirect('/?message=Logout+successful&type=success');
    });
});



// Start the server
app.listen(port, () => {
    console.log(`Server started on http://localhost:${port}`);
});
*/


/*const express = require('express'); 
const mongoose = require('mongoose');
const path = require('path');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const crypto = require('crypto');
const fs = require('fs');
const session = require('express-session');
const port = 3019;

const app = express();

// Set the view engine to EJS
app.set('view engine', 'ejs');

// Middleware
app.use(express.static(__dirname));
app.use(express.urlencoded({ extended: true }));

// Initialize session
app.use(session({
    secret: 'your_secret_key', // Change this to a secure random string
    resave: false,
    saveUninitialized: true,
}));

// Ensure the upload directory exists
if (!fs.existsSync('uploads')) {
    fs.mkdirSync('uploads');
}

// MongoDB Connection
mongoose.connect('mongodb://127.0.0.1:27017/Customer').then(() => console.log('MongoDB connection successful'))
    .catch((error) => console.error('MongoDB connection error:', error));

// Encryption setup
const algorithm = 'aes-256-gcm';
const secretKey = crypto.randomBytes(32);
const iv = crypto.randomBytes(16);

function encrypt(text) {
    const cipher = crypto.createCipheriv(algorithm, secretKey, iv);
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    const authTag = cipher.getAuthTag().toString('hex');
    return {
        iv: iv.toString('hex'),
        encryptedData: encrypted,
        authTag: authTag
    };
}

// Decrypt function (optional if needed for admin review)
function decrypt(encryptedData, ivHex, authTagHex) {
    const decipher = crypto.createDecipheriv(algorithm, secretKey, Buffer.from(ivHex, 'hex'));
    decipher.setAuthTag(Buffer.from(authTagHex, 'hex'));
    let decrypted = decipher.update(encryptedData, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
}

// User Schema
const userSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    isAdmin: { type: Boolean, default: false } // Added isAdmin field
});

const User = mongoose.model('User', userSchema);

// Session Schema for storing login details
const sessionSchema = new mongoose.Schema({
    email: { type: String, required: true },
    loginDate: { type: Date, default: Date.now }
});

const Session = mongoose.model('Session', sessionSchema);

// Hostel Schema
const hostelSchema = new mongoose.Schema({
    name: { type: String, required: true },
    location: { type: String, required: true },
    rent: { type: Number, required: true },
    contactNumber: { type: String, required: true },
    description: String,
    image: String
});

const Hostel = mongoose.model('Hostel', hostelSchema, 'hostels');

// Payment Schema
const paymentSchema = new mongoose.Schema({
    hostelId: { type: mongoose.Schema.Types.ObjectId, ref: 'Hostel', required: true },
    userName: { type: String, required: true },
    contactNumber: { type: String, required: true },
    cardNumber: { type: String, required: true }, // Encrypted
    cardExpiry: { type: String, required: true }, // Encrypted
    cardCVV: { type: String, required: true }, // Encrypted
    iv: { type: String, required: true },
    authTag: { type: String, required: true },
    paymentDate: { type: Date, default: Date.now }
});

const Payment = mongoose.model('Payment', paymentSchema, 'payment');

// Multer storage configuration for image uploads
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, 'uploads/');
    },
    filename: function (req, file, cb) {
        cb(null, Date.now() + '-' + file.originalname);
    }
});

const upload = multer({ storage });

// Middleware to check if user is an admin
function isAdmin(req, res, next) {
    if (req.session.user && req.session.user.isAdmin) {
        return next();
    }
    res.redirect('/?message=Access+denied&type=error');
}

// Routes for authentication
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'login.html'));
});

app.get('/register', (req, res) => {
    res.sendFile(path.join(__dirname, 'register.html'));
});

app.get('/landing_page', (req, res) => {
    res.sendFile(path.join(__dirname, 'landing_page.html'));
});

app.get('/customersupport', (req, res) => {
    res.sendFile(path.join(__dirname, 'customersupport.html'));
});

// Handle registration
app.post('/register', async (req, res) => {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
        return res.redirect('/register?message=Missing+required+fields&type=error');
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const user = new User({ name, email, password: hashedPassword });
        await user.save();
        console.log('User registered:', user);
        res.redirect('/?message=Registration+successful&type=success');
    } catch (error) {
        if (error.code === 11000) {
            return res.redirect('/register?message=Email+already+exists&type=error');
        }
        console.error('Error registering user:', error);
        res.redirect('/register?message=Error+registering+user&type=error');
    }
});

// Handle login
app.post('/login', async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.redirect('/?message=Missing+email+or+password&type=error');
    }

    try {
        const user = await User.findOne({ email });
        if (!user) {
            return res.redirect('/?message=User+not+found&type=error');
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.redirect('/?message=Invalid+password&type=error');
        }

        // Store user information in session
        req.session.user = { id: user._id, name: user.name, email: user.email, isAdmin: user.isAdmin };
        console.log('User logged in:', user);

        // Log session data to MongoDB
        const sessionData = new Session({ email: user.email });
        await sessionData.save();

        // Redirect based on user role
        if (user.isAdmin) {
            return res.redirect('/admin_dashboard'); // Admin dashboard
        }

        res.redirect('/landing_page?message=Login+successful&type=success');
    } catch (error) {
        console.error('Error during login:', error);
        res.redirect('/?message=Error+during+login&type=error');
    }
});

// Admin manage hostels
app.get('/admin_dashboard', isAdmin, async (req, res) => {
    try {
        const users = await User.find({});
        const hostels = await Hostel.find({});
        const sessions = await Session.find({}); // Retrieve session data

        res.render('admin_dashboard', { user: req.session.user, users, hostels, sessions });
    } catch (error) {
        console.error('Error fetching admin data:', error);
        res.status(500).send('Error fetching admin data');
    }
});

// Logout route
app.get('/logout', (req, res) => {
    // Destroy the session
    req.session.destroy((err) => {
        if (err) {
            console.error('Error logging out:', err);
            return res.redirect('/?message=Error+logging+out&type=error');
        }
        res.redirect('/?message=Logout+successful&type=success');
    });
});

// Start the server
app.listen(port, () => {
    console.log(`Server started on http://localhost:${port}`);
});
 */









const express = require('express'); 
const mongoose = require('mongoose');
const path = require('path');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const crypto = require('crypto');
const fs = require('fs');
const session = require('express-session');
const port = 3020;

const app = express();

// Set the view engine to EJS
app.set('view engine', 'ejs');

// Middleware
app.use(express.static(__dirname));
app.use(express.urlencoded({ extended: true }));

// Initialize session
app.use(session({
    secret: 'your_secret_key', // Change this to a secure random string
    resave: false,
    saveUninitialized: true,
}));

// Ensure the upload directory exists
if (!fs.existsSync('uploads')) {
    fs.mkdirSync('uploads');
}

// MongoDB Connection
mongoose.connect('mongodb://127.0.0.1:27017/Customer').then(() => console.log('MongoDB connection successful'))
    .catch((error) => console.error('MongoDB connection error:', error));

// Encryption setup
const algorithm = 'aes-256-gcm';
const secretKey = crypto.randomBytes(32);
const iv = crypto.randomBytes(16);

function encrypt(text) {
    const cipher = crypto.createCipheriv(algorithm, secretKey, iv);
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    const authTag = cipher.getAuthTag().toString('hex');
    return {
        iv: iv.toString('hex'),
        encryptedData: encrypted,
        authTag: authTag
    };
}

// Decrypt function (optional if needed for admin review)
function decrypt(encryptedData, ivHex, authTagHex) {
    const decipher = crypto.createDecipheriv(algorithm, secretKey, Buffer.from(ivHex, 'hex'));
    decipher.setAuthTag(Buffer.from(authTagHex, 'hex'));
    let decrypted = decipher.update(encryptedData, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
}

// User Schema
const userSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    isAdmin: { type: Boolean, default: false } // Added isAdmin field
});

const User = mongoose.model('User', userSchema);

// Hostel Schema
const hostelSchema = new mongoose.Schema({
    name: { type: String, required: true },
    location: { type: String, required: true },
    rent: { type: Number, required: true },
    contactNumber: { type: String, required: true },
    description: String,
    image: String
});

const Hostel = mongoose.model('Hostel', hostelSchema, 'hostels');

// Payment Schema
const paymentSchema = new mongoose.Schema({
    hostelId: { type: mongoose.Schema.Types.ObjectId, ref: 'Hostel', required: true },
    userName: { type: String, required: true },
    contactNumber: { type: String, required: true },
    cardNumber: { type: String, required: true }, // Encrypted
    cardExpiry: { type: String, required: true }, // Encrypted
    cardCVV: { type: String, required: true }, // Encrypted
    iv: { type: String, required: true },
    authTag: { type: String, required: true },
    paymentDate: { type: Date, default: Date.now }
});

const Payment = mongoose.model('Payment', paymentSchema, 'payment');

// Multer storage configuration for image uploads
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, 'uploads/');
    },
    filename: function (req, file, cb) {
        cb(null, Date.now() + '-' + file.originalname);
    }
});

const upload = multer({ storage });

// Middleware to check if user is an admin
function isAdmin(req, res, next) {
    if (req.session.user && req.session.user.isAdmin) {
        return next();
    }
    res.redirect('/?message=Access+denied&type=error');
}

// Routes for authentication
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'login.html'));
});

app.get('/register', (req, res) => {
    res.sendFile(path.join(__dirname, 'register.html'));
});

app.get('/landing_page', (req, res) => {
    res.sendFile(path.join(__dirname, 'landing_page.html'));
});

app.get('/customersupport', (req, res) => {
    res.sendFile(path.join(__dirname, 'customersupport.html'));
});

// Handle registration
app.post('/register', async (req, res) => {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
        return res.redirect('/register?message=Missing+required+fields&type=error');
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const user = new User({ name, email, password: hashedPassword });
        await user.save();
        console.log('User registered:', user);
        res.redirect('/?message=Registration+successful&type=success');
    } catch (error) {
        if (error.code === 11000) {
            return res.redirect('/register?message=Email+already+exists&type=error');
        }
        console.error('Error registering user:', error);
        res.redirect('/register?message=Error+registering+user&type=error');
    }
});

// Handle login
app.post('/login', async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.redirect('/?message=Missing+email+or+password&type=error');
    }

    try {
        const user = await User.findOne({ email });
        if (!user) {
            return res.redirect('/?message=User+not+found&type=error');
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.redirect('/?message=Invalid+password&type=error');
        }

        // Store user information in session
        req.session.user = { id: user._id, name: user.name, isAdmin: user.isAdmin };
        console.log('User logged in:', user); // Log the logged-in user

        // Redirect based on whether the user is an admin
        if (user.isAdmin) {
            return res.redirect('/admin_dashboard'); // Redirect to admin dashboard
        }

        // Redirect to regular landing page for non-admin users
        res.redirect('/landing_page?message=Login+successful&type=success');
    } catch (error) {
        console.error('Error during login:', error);
        res.redirect('/?message=Error+during+login&type=error');
    }
});



//admin hostel delete
app.post('/admin/hostels/delete/:id', isAdmin, async (req, res) => {
    try {
        await Hostel.findByIdAndDelete(req.params.id);
        res.redirect('/admin_hostels?message=Hostel+successfully+deleted&type=success');
    } catch (error) {
        console.error('Error deleting hostel:', error);
        res.status(500).send('Error deleting hostel');
    }
});

//admin hostel edit
app.get('/admin/hostels/edit/:id', isAdmin, async (req, res) => {
    try {
        const hostel = await Hostel.findById(req.params.id);
        if (!hostel) {
            return res.status(404).send('Hostel not found');
        }
        res.render('admin_edit_hostel', { hostel });
    } catch (error) {
        console.error('Error fetching hostel:', error);
        res.status(500).send('Error fetching hostel');
    }
});


// Hostel form route
app.get('/hostel_form', (req, res) => {
    res.sendFile(path.join(__dirname, 'hostel_form.html'));
});

// Handle hostel form submission
app.post('/submit_hostel', upload.single('hostelImage'), async (req, res) => {
    const { hostelName, hostelLocation, hostelRent, hostelContact, hostelDescription } = req.body;
    const hostelImage = req.file ? req.file.path : null;

    if (!hostelName || !hostelLocation || !hostelRent || !hostelContact || !hostelImage) {
        return res.redirect('/hostel_form?message=Missing+required+fields&type=error');
    }

    try {
        const hostel = new Hostel({
            name: hostelName,
            location: hostelLocation,
            rent: hostelRent,
            contactNumber: hostelContact,
            description: hostelDescription,
            image: hostelImage
        });
        await hostel.save();
        console.log('Hostel data saved:', hostel);
        res.redirect('/hostel_form?message=Hostel+data+successfully+submitted&type=success');
    } catch (error) {
        console.error('Error submitting hostel data:', error);
        res.redirect('/hostel_form?message=Error+submitting+hostel+data&type=error');
    }
});


app.post('/admin/hostels/edit/:id', isAdmin, upload.single('hostelImage'), async (req, res) => {
    const { hostelName, hostelLocation, hostelRent, hostelContact, hostelDescription } = req.body;
    const hostelImage = req.file ? req.file.path : req.body.currentImage;  // Check if a new image was uploaded

    try {
        await Hostel.findByIdAndUpdate(req.params.id, {
            name: hostelName,
            location: hostelLocation,
            rent: hostelRent,
            contactNumber: hostelContact,
            description: hostelDescription,
            image: hostelImage
        });
        res.redirect('/admin_hostels?message=Hostel+successfully+updated&type=success');
    } catch (error) {
        console.error('Error updating hostel:', error);
        res.status(500).send('Error updating hostel');
    }
});


app.post('/admin/hostels/new', isAdmin, upload.single('hostelImage'), async (req, res) => {
    const { hostelName, hostelLocation, hostelRent, hostelContact, hostelDescription } = req.body;
    const hostelImage = req.file ? req.file.path : null;

    if (!hostelName || !hostelLocation || !hostelRent || !hostelContact || !hostelImage) {
        return res.redirect('/admin/hostels/new?message=Missing+required+fields&type=error');
    }

    try {
        const hostel = new Hostel({
            name: hostelName,
            location: hostelLocation,
            rent: hostelRent,
            contactNumber: hostelContact,
            description: hostelDescription,
            image: hostelImage
        });
        await hostel.save();
        res.redirect('/admin_hostels?message=Hostel+added+successfully&type=success');
    } catch (error) {
        console.error('Error adding hostel:', error);
        res.status(500).send('Error adding hostel');
    }
});


// Display hostels
app.get('/hostels', async (req, res) => {
    try {
        const hostels = await Hostel.find({});
        res.render('hostels', { hostels });
    } catch (error) {
        console.error('Error fetching hostels:', error);
        res.status(500).send('Error fetching hostels');
    }
});

app.get('/admin_dashboard', isAdmin, async (req, res) => {
    try {
        const users = await User.find({});
        const hostels = await Hostel.find({});
        res.render('admin_dashboard', { user: req.session.user, users, hostels }); // Pass the user object here
    } catch (error) {
        console.error('Error fetching admin data:', error);
        res.status(500).send('Error fetching admin data');
    }
});


// Payment page route
app.get('/payment', async (req, res) => {
    const { hostelId } = req.query;

    try {
        const hostel = await Hostel.findById(hostelId);
        if (!hostel) return res.status(404).send('Hostel not found');
        res.render('payment', { hostel });
    } catch (error) {
        console.error('Error fetching hostel for payment:', error);
        res.status(500).send('Error fetching hostel for payment');
    }
});

// Process payment (with encryption)
app.post('/process_payment', async (req, res) => {
    const { hostelId, userName, contactNumber, cardNumber, cardExpiry, cardCVV } = req.body;

    try {
        const encryptedCardNumber = encrypt(cardNumber);
        const encryptedCardExpiry = encrypt(cardExpiry);
        const encryptedCardCVV = encrypt(cardCVV);

        const payment = new Payment({
            hostelId,
            userName,
            contactNumber,
            cardNumber: encryptedCardNumber.encryptedData,
            cardExpiry: encryptedCardExpiry.encryptedData,
            cardCVV: encryptedCardCVV.encryptedData,
            iv: encryptedCardNumber.iv, 
            authTag: encryptedCardNumber.authTag 
        });

        await payment.save();
        console.log('Payment saved successfully:', payment);
        res.redirect(`/payment_success?hostelId=${hostelId}&userName=${userName}`);
    } catch (error) {
        console.error('Error processing payment:', error);
        res.status(500).send('Error processing payment');
    }
});

// Payment success page
app.get('/payment_success', async (req, res) => {
    const { hostelId, userName } = req.query;

    try {
        const hostel = await Hostel.findById(hostelId);
        if (!hostel) return res.status(404).send('Hostel not found');
        res.render('payment_success', {
            userName,
            hostelName: hostel.name,
            hostelRent: hostel.rent
        });
    } catch (error) {
        console.error('Error fetching hostel for payment success:', error);
        res.status(500).send('Error fetching hostel for payment success');
    }
});


// Admin manage hostels
app.get('/admin_hostels', isAdmin, async (req, res) => {
    try {
        const hostels = await Hostel.find({});
        res.render('admin_hostels', { hostels });
    } catch (error) {
        console.error('Error fetching hostels:', error);
        res.status(500).send('Error fetching hostels');
    }
});

// Admin add new hostel
app.get('/admin_new_hostel', isAdmin, (req, res) => {
    res.render('admin_new_hostel');
});

// Admin edit hostel
app.get('/admin_edit_hostel/:id', isAdmin, async (req, res) => {
    try {
        const hostel = await Hostel.findById(req.params.id);
        if (!hostel) {
            return res.status(404).send('Hostel not found');
        }
        res.render('admin_edit_hostel', { hostel });
    } catch (error) {
        console.error('Error fetching hostel:', error);
        res.status(500).send('Error fetching hostel');
    }
});

//admin add hostel
app.get('/admin/hostels/new', isAdmin, (req, res) => {
    res.render('admin_new_hostel');
});

//admin view user
app.get('/admin/users', isAdmin, async (req, res) => {
    try {
        const users = await User.find({});
        res.render('admin_users', { users });
    } catch (error) {
        console.error('Error fetching users:', error);
        res.status(500).send('Error fetching users');
    }
});

// Logout route
app.get('/logout', (req, res) => {
    // Destroy the session
    req.session.destroy((err) => {
        if (err) {
            console.error('Error logging out:', err);
            return res.redirect('/?message=Error+logging+out&type=error');
        }

        // Redirect to the login page after successful logout
        res.redirect('/?message=Logout+successful&type=success');
    });
});



// Start the server
app.listen(port, () => {
    console.log(`Server started on http://localhost:${port}`);
});
