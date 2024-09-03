const express = require('express');
const session = require('express-session');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const bcrypt = require('bcrypt');
const mongoose = require('mongoose');
const path = require('path');
const nodemailer = require('nodemailer');
const shortid = require('shortid');
const expressLayouts = require('express-ejs-layouts');
const dotenv = require('dotenv');
const crypto = require('crypto');
const axios = require('axios');
const QRCode = require('qrcode');
const useragent = require('express-useragent');
const geoip = require('geoip-lite');
const flash = require('connect-flash');
const rateLimit = require('express-rate-limit');
dotenv.config();

const app = express();
const port = process.env.PORT || 3000;

// Log the current time
console.log(new Date().toISOString());

// MongoDB connection
mongoose.connect(process.env.MongoURI).then(() => console.log('MongoDB connected...'))
  .catch(err => console.error('MongoDB connection error:', err));

// Define MongoDB schemas and models
const userSchema = new mongoose.Schema({
  email: { type: String, unique: true, required: true },
  password: { type: String, required: true },
  verified: { type: Boolean, default: false },
  email_notifications: { type: Boolean, default: true },
  verification_token: String,
  reset_token: String,
  reset_token_expires: Date,
  created_at: { type: Date, default: Date.now }
});

const urlSchema = new mongoose.Schema({
  user_id: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  original_url: { type: String, required: true },
  short_code: { type: String, unique: true, required: true },
  custom_alias: { type: String, unique: true, sparse: true },
  created_at: { type: Date, default: Date.now },
  max_uses: Number,
  auto_delete_at: Date,
  whitelist_mode: { type: Boolean, default: false },
  allowed_countries: [String],
  blocked_countries: [String],
  password: String
});

const clickSchema = new mongoose.Schema({
  url_id: { type: mongoose.Schema.Types.ObjectId, ref: 'Url', required: true },
  clicked_at: { type: Date, default: Date.now },
  country: String,
  browser: String,
  device: String
});

const failedAttemptSchema = new mongoose.Schema({
  url_id: { type: mongoose.Schema.Types.ObjectId, ref: 'Url', required: true },
  attempted_at: { type: Date, default: Date.now },
  ip_address: String
});

const User = mongoose.model('User', userSchema);
const Url = mongoose.model('Url', urlSchema);
const Click = mongoose.model('Click', clickSchema);
const FailedAttempt = mongoose.model('FailedAttempt', failedAttemptSchema);

// Middleware
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(expressLayouts);
app.set('layout', 'layout');
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(session({
  secret: process.env.SESSION_SECRET || 'your-secret-key',
  resave: false,
  saveUninitialized: false
}));
app.use(passport.initialize());
app.use(passport.session());
app.use(useragent.express());
app.use(flash());

// Rate limiting configuration
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // limit each IP to 100 requests per windowMs
});

// Apply rate limiting to all requests
app.use(limiter);

// More specific rate limiters
const createAccountLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour window
  max: 5, // start blocking after 5 requests
  message: "Too many accounts created from this IP, please try again after an hour"
});

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // start blocking after 5 requests
  message: "Too many login attempts from this IP, please try again after 15 minutes"
});

const urlShortenLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour window
  max: 10, // start blocking after 10 requests
  message: "Too many URLs shortened from this IP, please try again after an hour"
});

// Function to delete expired URLs
async function deleteExpiredUrls() {
  const now = new Date();
  try {
    const expiredUrls = await Url.find({
      auto_delete_at: { $lte: now, $ne: null }
    });

    for (const url of expiredUrls) {
      await Click.deleteMany({ url_id: url._id });
      await FailedAttempt.deleteMany({ url_id: url._id });
      await Url.findByIdAndDelete(url._id);
    }

    console.log('Expired URLs and associated data deleted successfully');
  } catch (error) {
    console.error('Error deleting expired URLs:', error);
  }
}

// Run deleteExpiredUrls every minute
setInterval(deleteExpiredUrls, 60000);

async function checkUrlAboutToExpire() {
  const now = new Date();
  const in24Hours = new Date(now.getTime() + 24 * 60 * 60 * 1000);
  try {
    const userUrls = await Url.aggregate([
      {
        $match: {
          created_at: { $lte: now, $ne: null },
          auto_delete_at: { $gt: now, $lt: in24Hours, $ne: null },
        },
      },
      {
        $group: {
          _id: "$user_id",
          urls: { $push: "$$ROOT" }, // Push all matched documents into an array under 'urls'
        },
      },
    ]);

    for (const userUrl of userUrls) {
      const user = await User.findById(userUrl._id);
      if(!user.email_notifications) {
        continue;
      }
      const subject = "URLs about to expire";

      const text = `Hello,\nThis is a reminder that the following URLs are about to expire in 24 hours:\n\n`;
      const urlsToExpire = userUrl.urls.map((url) => `•URL: ${url.short_code}`).join("\n");

      const mailOptions = {
        from: process.env.login,
        to: user.email,
        subject: subject,
        text: text + urlsToExpire,
      };
    
      sendEmail(mailOptions);
      console.log('Email sent to', user.email, 'about URLs about to expire');
    }
  } catch (error) {
    console.error("Error checking URLs about to expire:", error);
  }
}

// Run checkUrlAboutToExpire every 24 hours
setInterval(checkUrlAboutToExpire, 86400000);

async function sendEmail({ from, to, subject, text }) {
  
  const mailOptions = {
    from: from,
    to: to,
    subject: subject,
    text: text
  };

  try {
    await transporter.sendMail(mailOptions);
  }catch (error) {
    console.error('Error sending email:', error);
  }
}

// Logging function
function log(message, data = {}) {
  console.log(JSON.stringify({ timestamp: new Date().toISOString(), message, ...data }));
}

// Passport configuration
passport.use(new LocalStrategy(
  { usernameField: 'email' },
  async (email, password, done) => {
    try {
      const user = await User.findOne({ email: email });
      if (!user) return done(null, false, { message: 'Incorrect email.' });
      if (!user.verified) return done(null, false, { message: 'Email not verified.' });
      
      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch) return done(null, false, { message: 'Incorrect password.' });
      return done(null, user);
    } catch (err) {
      return done(err);
    }
  }
));

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (err) {
    done(err);
  }
});

// Nodemailer configuration
const transporter = nodemailer.createTransport({
  host: 'smtp.office365.com',
  port: 587,
  secure: false,
  auth: {
    user: process.env.login,
    pass: process.env.password
  }
});

console.log('Verifying transporter connection...');
transporter.verify(function(error, success) {
  if (error) {
    console.log('Transporter verification error:', error);
  } else {
    console.log('Transporter is ready to send emails');
  }
});

// Routes
app.get('/', (req, res) => {
  res.render('index', { user: req.user });
});

app.get('/logout', (req, res) => {
  req.logout(() => {
    res.redirect('/');
  });
});

app.get('/login', (req, res) => {
  res.render('login', { message: req.flash('error') });
});

app.post('/login', loginLimiter, passport.authenticate('local', {
  successRedirect: '/dashboard',
  failureRedirect: '/login',
  failureFlash: true
}));

app.get('/register', (req, res) => {
  res.render('register', { message: req.flash('error') });
});

app.post('/register', createAccountLimiter, async (req, res) => {
  const { email, password } = req.body;
  try {
    const existingUser = await User.findOne({ email: email });
    if (existingUser) {
      req.flash('error', 'Email already exists');
      return res.redirect('/register');
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const verificationToken = crypto.randomBytes(32).toString('hex');
    
    const newUser = new User({
      email: email,
      password: hashedPassword,
      verified: false,
      email_notifications: true,
      verification_token: verificationToken
    });

    await newUser.save();
    
    // Send verification email
    // get the actual base URL from the request
    const baseUrl = `${req.protocol}://${req.get('host')}`;
    const verificationLink = `${baseUrl}/verify/${verificationToken}`;
    const mailOptions = {
      from: process.env.login,
      to: email,
      subject: 'Verify your email for URL Slicer',
      text: `Please click on this link to verify your email: ${verificationLink}`
    };
    
    sendEmail(mailOptions);
    res.redirect('/register-confirmation');
  } catch (error) {
    console.log(error);
    req.flash('error', 'Error registering user');
    res.redirect('/register');
  }
});

app.get('/register-confirmation', (req, res) => {
  res.render('register-confirmation');
});

app.get('/verify/:token', async (req, res) => {
  const { token } = req.params;
  try {
    const user = await User.findOneAndUpdate(
      { verification_token: token },
      { verified: true, $unset: { verification_token: 1 } },
      { new: true }
    );
    if (!user) {
      return res.send('Invalid verification token');
    }
    res.render('verification-success');
  } catch (error) {
    console.error(error);
    res.send('Error verifying email');
  }
});

app.get('/dashboard', async (req, res) => {
  if (!req.user) {
    return res.redirect('/login');
  }
  try {
    const urls = await Url.find({ user_id: req.user._id });
    res.render('dashboard', { user: req.user, urls: urls });
  } catch (error) {
    console.error(error);
    res.status(500).send('Error fetching URLs');
  }
});

app.post('/shorten', urlShortenLimiter, async (req, res) => {
  if (!req.user) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const { originalUrl, maxUses, autoDeleteAt, whitelistMode, allowedCountries, blockedCountries, customAlias, password } = req.body;
  const shortCode = customAlias || shortid.generate();

  // Check if the custom alias is valid (3-50 symbols)
  if (customAlias && (customAlias.length < 3 || customAlias.length > 50)) {
    return res.status(400).json({ error: 'Custom alias must be between 3 and 50 symbols' });
  }

  try {
    // Check if the custom alias or short code is already taken
    const existingUrl = await Url.findOne({
      $or: [{ short_code: shortCode }, { custom_alias: customAlias }]
    });

    if (existingUrl) {
      return res.status(400).json({ error: 'The custom alias or generated short code is already taken' });
    }

    // If the alias is not taken, create the URL
    const newUrl = new Url({
      user_id: req.user._id,
      original_url: originalUrl,
      short_code: shortCode,
      custom_alias: customAlias,
      max_uses: maxUses,
      auto_delete_at: autoDeleteAt,
      whitelist_mode: whitelistMode,
      allowed_countries: allowedCountries,
      blocked_countries: blockedCountries,
      password: password
    });

    await newUrl.save();
    res.json({ shortCode: shortCode, customAlias: customAlias });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error creating shortened URL' });
  }
});

// New routes for password reset
app.get('/forgot-password', (req, res) => {
  res.render('forgot-password');
});

app.post('/forgot-password', async (req, res) => {
  const { email } = req.body;
  try {
    const user = await User.findOne({ email: email });
    if (!user) {
      return res.render('forgot-password', { error: 'No account with that email address exists.' });
    }

    const resetToken = crypto.randomBytes(20).toString('hex');
    const resetTokenExpires = Date.now() + 24 * 60 * 60 * 1000; // 24 hours from now

    user.reset_token = resetToken;
    user.reset_token_expires = resetTokenExpires;
    await user.save();

    const resetUrl = `${req.protocol}://${req.get('host')}/reset-password/${resetToken}`;
    const mailOptions = {
      from: process.env.login,
      to: user.email,
      subject: 'Password Reset for URL Slicer',
      text: `You are receiving this because you (or someone else) have requested the reset of the password for your account.\n\n
        Please click on the following link, or paste this into your browser to complete the process:\n\n
        ${resetUrl}\n\n
        If you did not request this, please ignore this email and your password will remain unchanged.\n`
    };

    sendEmail(mailOptions);
    res.render('forgot-password', { message: 'An email has been sent to ' + user.email + ' with further instructions.' });
  } catch (error) {
    console.error(error);
    res.render('forgot-password', { error: 'An error occurred while sending the email. Please try again.' });
  }
});

app.get('/reset-password/:token', async (req, res) => {
  const { token } = req.params;
  try {
    const user = await User.findOne({
      reset_token: token,
      reset_token_expires: { $gt: Date.now() }
    });

    if (!user) {
      return res.render('reset-password', { error: 'Password reset token is invalid or has expired.' });
    }

    res.render('reset-password', { token });
  } catch (error) {
    console.error(error);
    res.render('reset-password', { error: 'An error occurred. Please try again.' });
  }
});

app.post('/reset-password', async (req, res) => {
  const { token, password, confirmPassword } = req.body;

  if (password !== confirmPassword) {
    return res.render('reset-password', { token, error: 'Passwords do not match.' });
  }

  try {
    const user = await User.findOne({
      reset_token: token,
      reset_token_expires: { $gt: Date.now() }
    });

    if (!user) {
      return res.render('reset-password', { error: 'Password reset token is invalid or has expired.' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    user.password = hashedPassword;
    user.reset_token = undefined;
    user.reset_token_expires = undefined;
    await user.save();

    res.redirect('/login');
  } catch (error) {
    console.error(error);
    res.render('reset-password', { error: 'An error occurred. Please try again.' });
  }
});

// Add the new route for the analytics page
app.get('/analytics', (req, res) => {
  if (!req.user) {
    return res.redirect('/login');
  }
  res.render('analytics', { user: req.user });
});

app.get('/api/analytics', async (req, res) => {
  if (!req.user) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  try {
    const totalClicks = await Click.countDocuments({ url_id: { $in: await Url.find({ user_id: req.user._id }).distinct('_id') } });
    const totalUrls = await Url.countDocuments({ user_id: req.user._id });
    const averageCTR = totalUrls > 0 ? totalClicks / totalUrls : 0;
    
    const ctrOverTime = await Click.aggregate([
      { $match: { url_id: { $in: await Url.find({ user_id: req.user._id }).distinct('_id') } } },
      { $group: {
        _id: { $dateToString: { format: "%Y-%m-%d", date: "$clicked_at" } },
        clicks: { $sum: 1 }
      }},
      { $sort: { _id: 1 } }
    ]);

    const deviceStats = await Click.aggregate([
      { $match: { url_id: { $in: await Url.find({ user_id: req.user._id }).distinct('_id') } } },
      { $group: {
        _id: "$device",
        count: { $sum: 1 }
      }}
    ]);

    const browserStats = await Click.aggregate([
      { $match: { url_id: { $in: await Url.find({ user_id: req.user._id }).distinct('_id') } } },
      { $group: {
        _id: "$browser",
        count: { $sum: 1 }
      }}
    ]);

    res.json({
      totalClicks,
      totalUrls,
      averageCTR,
      ctrOverTime,
      deviceStats,
      browserStats
    });
  } catch (error) {
    console.error('Error fetching analytics data:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/country-stats/:code', async (req, res) => {
  if (!req.user) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const { code } = req.params;
  try {
    const url = await Url.findOne({
      $or: [{ short_code: code }, { custom_alias: code }],
      user_id: req.user._id
    });

    if (!url) {
      return res.status(404).json({ error: 'URL not found' });
    }

    const countryStats = await Click.aggregate([
      { $match: { url_id: url._id } },
      { $group: { _id: "$country", count: { $sum: 1 } } },
      { $sort: { count: -1 } }
    ]);

    res.json(countryStats);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error fetching country statistics' });
  }
});

// Add this new route for the account management page
app.get('/account', (req, res) => {
  if (!req.user) {
    return res.redirect('/login');
  }
  res.render('account', { user: req.user });
});

// Add this new route for updating email notifications preferences
app.post('/account/email-notifications', async (req, res) => {
  if(!req.user) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const { emailNotifications } = req.body;

  try {
    const user = await User.findById(req.user._id);
    user.email_notifications = emailNotifications;
    await user.save();
    res.json({ message: 'Email notifications updated successfully' });
  } catch (error) {
    console.error('Error updating email notifications:', error);
    res.status(500).json({ error: 'An error occurred while updating email notifications' });
  }
});

// Add this new route for changing the password
app.post('/account/change-password', async (req, res) => {
  if (!req.user) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const { currentPassword, newPassword } = req.body;

  try {
    const user = await User.findById(req.user._id);
    const isMatch = await bcrypt.compare(currentPassword, user.password);
    if (!isMatch) {
      return res.status(400).json({ error: 'Current password is incorrect' });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedPassword;
    await user.save();

    res.json({ message: 'Password changed successfully' });
  } catch (error) {
    console.error('Error changing password:', error);
    res.status(500).json({ error: 'An error occurred while changing the password' });
  }
});

// Add this new route for deleting the account
app.post('/account/delete', async (req, res) => {
  if (!req.user) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  try {
    // Delete user's URLs and associated data
    const userUrls = await Url.find({ user_id: req.user._id });
    for (const url of userUrls) {
      await Click.deleteMany({ url_id: url._id });
      await FailedAttempt.deleteMany({ url_id: url._id });
    }
    await Url.deleteMany({ user_id: req.user._id });

    // Delete user's account
    await User.findByIdAndDelete(req.user._id);

    req.logout(() => {
      res.json({ message: 'Account deleted successfully' });
    });
  } catch (error) {
    console.error('Error deleting account:', error);
    res.status(500).json({ error: 'An error occurred while deleting the account' });
  }
});

// Add this function to get the client's IP address
function getClientIp(req) {
  return req.headers['x-forwarded-for']?.split(',').shift()
    || req.socket?.remoteAddress;
}

app.get('/:code', async (req, res) => {
  const { code } = req.params;
  log('Accessing URL', { code });

  try {
    const url = await Url.findOne({ $or: [{ short_code: code }, { custom_alias: code }] });

    if (!url) {
      log('URL not found', { code });
      return res.status(404).render('url-not-found');
    }

    log('URL found', { url });

    // Check if the URL is password protected
    if (url.password) {
      // Render the password entry page
      return res.render('password-entry', { code: code });
    }

    const ip = getClientIp(req);
    log('Client IP', { ip });

    let country = 'Unknown';
    const geo = geoip.lookup(ip);
    if (geo) {
      country = geo.country;
      log('Country detected', { country, ip });
    } else {
      log('Failed to detect country with geoip, trying external API', { ip });
      try {
        const response = await axios.get(`http://ip-api.com/json/${ip}`);
        country = response.data.countryCode;
        log('Country detected from external API', { country });
      } catch (apiError) {
        log('Failed to detect country from external API', { error: apiError.message });
      }
    }

    if (url.whitelist_mode) {
      log('Whitelist mode', { allowedCountries: url.allowed_countries });
      if (!url.allowed_countries.includes(country)) {
        log('Access denied: country not in whitelist', { country });
        return res.status(403).render('access-denied');
      }
    } else {
      log('Blacklist mode', { blockedCountries: url.blocked_countries });
      if (url.blocked_countries.includes(country)) {
        log('Access denied: country in blocklist', { country });
        return res.status(403).render('access-denied');
      }
    }

    const clickCount = await Click.countDocuments({ url_id: url._id });

    log('Current click count', { clickCount, maxUses: url.max_uses });

    if (url.max_uses !== null && url.max_uses > 0 && clickCount >= url.max_uses) {
      log('Max uses reached', { clickCount, maxUses: url.max_uses });
      return res.status(410).render('max-uses-reached');
    }

    const userAgent = req.useragent;
    await Click.create({
      url_id: url._id,
      country: country,
      browser: userAgent.browser,
      device: userAgent.isMobile ? 'Mobile' : (userAgent.isTablet ? 'Tablet' : 'Desktop')
    });

    console.log('The user agent uses ' + userAgent.browser + ' on a ' + (userAgent.isMobile ? 'mobile' : (userAgent.isTablet ? 'tablet' : 'desktop')) + ' device.');

    log('Click recorded', { urlId: url._id, country, browser: userAgent.browser, device: userAgent.isMobile ? 'Mobile' : (userAgent.isTablet ? 'Tablet' : 'Desktop') });
    log('Redirecting', { originalUrl: url.original_url });
    res.redirect(url.original_url);

  } catch (error) {
    log('Error processing request', { error: error.message, stack: error.stack });
    res.status(500).send('An error occurred while processing your request');
  }
});

app.post('/:code/verify', async (req, res) => {
  const { code } = req.params;
  const { password } = req.body;
  const ip = req.ip;

  try {
    const url = await Url.findOne({ $or: [{ short_code: code }, { custom_alias: code }] });

    if (!url) {
      return res.status(404).json({ error: 'URL not found' });
    }

    const now = new Date();
    const fiveMinutesAgo = new Date(now - 5 * 60 * 1000);
    const halfHourAgo = new Date(now - 30 * 60 * 1000);
    const oneDayAgo = new Date(now - 24 * 60 * 60 * 1000);
    const oneWeekAgo = new Date(now - 7 * 24 * 60 * 60 * 1000);

    const [fiveMinAttempts, halfHourAttempts, dayAttempts, weekAttempts] = await Promise.all([
      FailedAttempt.countDocuments({
        url_id: url._id,
        ip_address: ip,
        attempted_at: { $gt: fiveMinutesAgo }
      }),
      FailedAttempt.countDocuments({
        url_id: url._id,
        ip_address: ip,
        attempted_at: { $gt: halfHourAgo }
      }),
      FailedAttempt.countDocuments({
        url_id: url._id,
        ip_address: ip,
        attempted_at: { $gt: oneDayAgo }
      }),
      FailedAttempt.countDocuments({
        url_id: url._id,
        ip_address: ip,
        attempted_at: { $gt: oneWeekAgo }
      })
    ]);

    if (fiveMinAttempts >= 5) {
      return res.status(429).json({ error: 'Too many attempts. Please try again in 5 minutes.' });
    }

    if (halfHourAttempts >= 25) {
      return res.status(429).json({ error: 'Too many attempts. Please try again in 30 minutes.' });
    }

    if (dayAttempts >= 40) {
      return res.status(429).json({ error: 'Daily limit exceeded. Please try again tomorrow.' });
    }

    if (weekAttempts >= 75) {
      return res.status(429).json({ error: 'Weekly limit exceeded. Please try again next week.' });
    }

    if (password !== url.password) {
      // Record failed attempt
      await FailedAttempt.create({
        url_id: url._id,
        ip_address: ip,
        attempted_at: now
      });
      return res.status(401).json({ error: 'Incorrect password' });
    }

    // Password is correct, proceed with redirection
    res.json({ success: true, redirectUrl: url.original_url });

  } catch (error) {
    console.error('Error verifying password:', error);
    res.status(500).json({ error: 'An error occurred while verifying the password' });
  }
});

// Add a cleanup job to remove old failed attempts
const cleanupFailedAttempts = async () => {
  const oneWeekAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
  await FailedAttempt.deleteMany({ attempted_at: { $lt: oneWeekAgo } });
};

// Run the cleanup job every day
setInterval(cleanupFailedAttempts, 24 * 60 * 60 * 1000);

app.get('/stats/:code', async (req, res) => {
  if (!req.user) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const { code } = req.params;
  try {
    const url = await Url.findOne({
      $or: [{ short_code: code }, { custom_alias: code }],
      user_id: req.user._id
    });

    if (!url) {
      return res.status(404).json({ error: 'URL not found' });
    }

    const clicks = await Click.find({ url_id: url._id });
    const failedAttempts = await FailedAttempt.countDocuments({ url_id: url._id });

    res.json({ url, clicks, failedAttempts });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error fetching click statistics' });
  }
});

app.get('/url/:code', async (req, res) => {
  if (!req.user) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const { code } = req.params;
  try {
    const url = await Url.findOne({
      $or: [{ short_code: code }, { custom_alias: code }],
      user_id: req.user._id
    });

    if (!url) {
      return res.status(404).json({ error: 'URL not found' });
    }

    res.json(url);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error fetching URL' });
  }
});

app.put('/url/:code', async (req, res) => {
  if (!req.user) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const { code } = req.params;
  const { maxUses, autoDeleteAt, whitelistMode, allowedCountries, blockedCountries, password } = req.body;

  try {
    const url = await Url.findOneAndUpdate(
      {
        $or: [{ short_code: code }, { custom_alias: code }],
        user_id: req.user._id
      },
      {
        max_uses: maxUses,
        auto_delete_at: autoDeleteAt === '' ? null : autoDeleteAt,
        whitelist_mode: whitelistMode,
        allowed_countries: allowedCountries,
        blocked_countries: blockedCountries,
        password: password
      },
      { new: true }
    );

    if (!url) {
      return res.status(404).json({ error: 'URL not found' });
    }

    res.json({ message: 'URL updated successfully' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error updating URL' });
  }
});

app.delete('/url/:code', async (req, res) => {
  if (!req.user) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const { code } = req.params;

  try {
    const url = await Url.findOne({
      $or: [{ short_code: code }, { custom_alias: code }],
      user_id: req.user._id
    });

    if (!url) {
      return res.status(404).json({ error: 'URL not found' });
    }

    await Click.deleteMany({ url_id: url._id });
    await FailedAttempt.deleteMany({ url_id: url._id });
    await Url.findByIdAndDelete(url._id);

    res.json({ message: 'URL and associated data deleted successfully' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error deleting URL' });
  }
});

app.get('/find/:code', async (req, res) => {
  const { code } = req.params;
  try {
    const url = await Url.findOne({ $or: [{ short_code: code }, { custom_alias: code }] });
    if (!url) {
      return res.status(404).json({ error: 'URL not found' });
    }
    const fullUrl = `${req.protocol}://${req.get('host')}/${url.short_code}`;
    res.json({ fullUrl });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error finding URL' });
  }
});

// Debug route
app.get('/debug/:code', async (req, res) => {
  const { code } = req.params;
  try {
    const url = await Url.findOne({ $or: [{ short_code: code }, { custom_alias: code }] });
    if (!url) {
      return res.status(404).json({ error: 'URL not found' });
    }
    const clickCount = await Click.countDocuments({ url_id: url._id });
    const failedAttempts = await FailedAttempt.countDocuments({ url_id: url._id });
    res.json({ url, click_count: clickCount, failed_attempts: failedAttempts });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error fetching debug information' });
  }
});

app.get('/qr/:code', async (req, res) => {
  if (!req.user) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const { code } = req.params;
  
  try {
    const url = await Url.findOne({
      $or: [{ short_code: code }, { custom_alias: code }],
      user_id: req.user._id
    });

    if (!url) {
      return res.status(404).json({ error: 'URL not found' });
    }

    const fullUrl = `${req.protocol}://${req.get('host')}/${url.short_code}`;
    const qrCode = await QRCode.toDataURL(fullUrl);
    
    res.json({ qrCode });
  } catch (error) {
    console.error('Error generating QR code:', error);
    res.status(500).json({ error: 'An error occurred while generating the QR code' });
  }
});

// Helper functions for fetching analytics data
async function getTotalClicks(userId) {
  return Click.countDocuments({ url_id: { $in: await Url.find({ user_id: userId }).distinct('_id') } });
}

async function getTotalUrls(userId) {
  return Url.countDocuments({ user_id: userId });
}

async function getCTROverTime(userId) {
  const clicks = await Click.aggregate([
    { $match: { url_id: { $in: await Url.find({ user_id: userId }).distinct('_id') } } },
    {
      $group: {
        _id: { $dateToString: { format: "%Y-%m-%d", date: "$clicked_at" } },
        clicks: { $sum: 1 }
      }
    },
    { $sort: { _id: 1 } }
  ]);

  const urls = await Url.aggregate([
    { $match: { user_id: mongoose.Types.ObjectId(userId) } },
    {
      $group: {
        _id: { $dateToString: { format: "%Y-%m-%d", date: "$created_at" } },
        urls: { $sum: 1 }
      }
    },
    { $sort: { _id: 1 } }
  ]);

  const ctrData = clicks.map(click => {
    const urlCount = urls.find(url => url._id === click._id)?.urls || 1;
    return {
      date: click._id,
      ctr: click.clicks / urlCount
    };
  });

  return ctrData;
}

async function getGeoDistribution(userId) {
  const geoData = await Click.aggregate([
    { $match: { url_id: { $in: await Url.find({ user_id: userId }).distinct('_id') } } },
    {
      $group: {
        _id: "$country",
        count: { $sum: 1 }
      }
    }
  ]);

  console.log('Raw geoData:', geoData);

  const result = geoData.reduce((acc, item) => {
    if (item._id && item._id.length === 2) {  // Ensure the country code is valid
      acc[item._id] = item.count;
    }
    return acc;
  }, {});

  console.log('Processed geoData:', result);

  return result;
}


// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).send('Something broke!');
});

// Start the server
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});

// Graceful shutdown
process.on('SIGINT', async () => {
  console.log('Closing MongoDB connection...');
  try {
    await mongoose.connection.close();
    console.log('MongoDB connection closed.');
    process.exit(0);
  } catch (err) {
    console.error('Error closing MongoDB connection:', err);
    process.exit(1);
  }
});