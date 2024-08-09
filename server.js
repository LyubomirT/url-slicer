const express = require('express');
const session = require('express-session');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const bcrypt = require('bcrypt');
const sqlite3 = require('sqlite3').verbose();
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
dotenv.config();

const app = express();
const port = process.env.PORT || 3000;

// Log the current time
console.log(new Date().toISOString());

// Database setup
const db = new sqlite3.Database('./database.sqlite', sqlite3.OPEN_READWRITE | sqlite3.OPEN_CREATE);

// Enable foreign key support
db.run('PRAGMA foreign_keys = ON');

// Create users table if not exists
db.run(`CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT UNIQUE,
  password TEXT,
  verified BOOLEAN,
  verification_token TEXT,
  reset_token TEXT,
  reset_token_expires DATETIME
)`);

// Create urls table if not exists (modified to include password field)
db.run(`CREATE TABLE IF NOT EXISTS urls (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER,
  original_url TEXT,
  short_code TEXT UNIQUE,
  custom_alias TEXT UNIQUE,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  max_uses INTEGER,
  auto_delete_at DATETIME,
  whitelist_mode BOOLEAN,
  allowed_countries TEXT,
  blocked_countries TEXT,
  password TEXT,
  FOREIGN KEY (user_id) REFERENCES users (id)
)`);

// Create clicks table if not exists
db.run(`CREATE TABLE IF NOT EXISTS clicks (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  url_id INTEGER,
  clicked_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  country TEXT,
  user_agent TEXT,
  FOREIGN KEY (url_id) REFERENCES urls (id)
)`);

// Create failed_attempts table
db.run(`CREATE TABLE IF NOT EXISTS failed_attempts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  url_id INTEGER,
  attempted_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  ip_address TEXT,
  FOREIGN KEY (url_id) REFERENCES urls (id)
)`);

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

// Function to delete expired URLs with enhanced error logging
function deleteExpiredUrls() {
  const now = new Date().toISOString();
  
  // Delete clicks for expired URLs
  db.run(`DELETE FROM clicks WHERE url_id IN (
    SELECT id FROM urls 
    WHERE auto_delete_at IS NOT NULL 
    AND auto_delete_at != '' 
    AND auto_delete_at <= ?
  )`, [now], (err) => {
    if (err) {
      console.error('Error deleting expired clicks:', err);
      console.error('Error details:', {
        message: err.message,
        code: err.code,
        errno: err.errno,
        sql: err.sql
      });
      return;
    }

    console.log('Expired clicks deleted successfully');

    // Delete expired URLs
    db.run(`DELETE FROM urls 
      WHERE auto_delete_at IS NOT NULL 
      AND auto_delete_at != '' 
      AND auto_delete_at <= ?`, [now], (err) => {
      if (err) {
        console.error('Error deleting expired URLs:', err);
        console.error('Error details:', {
          message: err.message,
          code: err.code,
          errno: err.errno,
          sql: err.sql
        });
      } else {
        console.log('Expired URLs deleted successfully');
      }
    });
  });
}

// Run deleteExpiredUrls every minute
setInterval(deleteExpiredUrls, 60000);

// Logging function
function log(message, data = {}) {
  console.log(JSON.stringify({ timestamp: new Date().toISOString(), message, ...data }));
}

// Passport configuration
passport.use(new LocalStrategy(
  { usernameField: 'email' },
  (email, password, done) => {
    db.get('SELECT * FROM users WHERE email = ?', [email], (err, user) => {
      if (err) return done(err);
      if (!user) return done(null, false, { message: 'Incorrect email.' });
      if (!user.verified) return done(null, false, { message: 'Email not verified.' });
      
      bcrypt.compare(password, user.password, (err, result) => {
        if (err) return done(err);
        if (!result) return done(null, false, { message: 'Incorrect password.' });
        return done(null, user);
      });
    });
  }
));

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser((id, done) => {
  db.get('SELECT * FROM users WHERE id = ?', [id], (err, user) => {
    done(err, user);
  });
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
  res.render('login');
});

app.post('/login', passport.authenticate('local', {
  successRedirect: '/dashboard',
  failureRedirect: '/login'
}));

app.get('/register', (req, res) => {
  res.render('register');
});

app.post('/register', async (req, res) => {
  const { email, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);
  const verificationToken = crypto.randomBytes(32).toString('hex');
  
  db.run('INSERT INTO users (email, password, verified, verification_token) VALUES (?, ?, ?, ?)', 
    [email, hashedPassword, false, verificationToken], 
    (err) => {
      if (err) {
        return res.render('register', { error: 'Email already exists' });
      }
      
      // Send verification email
      const verificationLink = `http://localhost:${port}/verify/${verificationToken}`;
      const mailOptions = {
        from: process.env.login,
        to: email,
        subject: 'Verify your email for URL Slicer',
        text: `Please click on this link to verify your email: ${verificationLink}`
      };
      
      transporter.sendMail(mailOptions, (error, info) => {
        if (error) {
          console.log(error);
          res.render('register', { error: 'Error sending email' });
        } else {
          console.log('Email sent: ' + info.response);
          res.redirect('/register-confirmation');
        }
      });
    }
  );
});

app.get('/register-confirmation', (req, res) => {
  res.render('register-confirmation');
});

app.get('/verify/:token', (req, res) => {
  const { token } = req.params;
  db.run('UPDATE users SET verified = ? WHERE verification_token = ?', [true, token], (err) => {
    if (err) {
      return res.send('Error verifying email');
    }
    res.render('verification-success');
  });
});

app.get('/dashboard', (req, res) => {
  if (!req.user) {
    return res.redirect('/login');
  }
  db.all('SELECT * FROM urls WHERE user_id = ?', [req.user.id], (err, urls) => {
    if (err) {
      console.error(err);
      return res.status(500).send('Error fetching URLs');
    }
    res.render('dashboard', { user: req.user, urls: urls });
  });
});

app.post('/shorten', (req, res) => {
  if (!req.user) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const { originalUrl, maxUses, autoDeleteAt, whitelistMode, allowedCountries, blockedCountries, customAlias, password } = req.body;
  const shortCode = customAlias || shortid.generate();

  // Check if the custom alias is valid (3-50 symbols)
  if (customAlias && (customAlias.length < 3 || customAlias.length > 50)) {
    return res.status(400).json({ error: 'Custom alias must be between 3 and 50 symbols' });
  }

  // Check if the custom alias or short code is already taken
  db.get('SELECT * FROM urls WHERE short_code = ? OR custom_alias = ?', [shortCode, customAlias], (err, existingUrl) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ error: 'Error checking for existing URL' });
    }

    if (existingUrl) {
      return res.status(400).json({ error: 'The custom alias or generated short code is already taken' });
    }

    // If the alias is not taken, proceed with creating the URL
    db.run(
      'INSERT INTO urls (user_id, original_url, short_code, custom_alias, max_uses, auto_delete_at, whitelist_mode, allowed_countries, blocked_countries, password) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
      [req.user.id, originalUrl, shortCode, customAlias, maxUses, autoDeleteAt, whitelistMode, allowedCountries, blockedCountries, password],
      function(err) {
        if (err) {
          console.error(err);
          return res.status(500).json({ error: 'Error creating shortened URL' });
        }
        res.json({ shortCode: shortCode, customAlias: customAlias });
      }
    );
  });
});

// New routes for password reset
app.get('/forgot-password', (req, res) => {
  res.render('forgot-password');
});

app.post('/forgot-password', (req, res) => {
  const { email } = req.body;
  db.get('SELECT * FROM users WHERE email = ?', [email], (err, user) => {
    if (err || !user) {
      return res.render('forgot-password', { error: 'No account with that email address exists.' });
    }

    const resetToken = crypto.randomBytes(20).toString('hex');
    const resetTokenExpires = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours from now

    db.run('UPDATE users SET reset_token = ?, reset_token_expires = ? WHERE id = ?', 
      [resetToken, resetTokenExpires.toISOString(), user.id], (err) => {
      if (err) {
        console.error(err);
        return res.render('forgot-password', { error: 'An error occurred. Please try again.' });
      }

      const resetUrl = `http://localhost:${port}/reset-password/${resetToken}`;
      const mailOptions = {
        from: process.env.login,
        to: user.email,
        subject: 'Password Reset for URL Slicer',
        text: `You are receiving this because you (or someone else) have requested the reset of the password for your account.\n\n
          Please click on the following link, or paste this into your browser to complete the process:\n\n
          ${resetUrl}\n\n
          If you did not request this, please ignore this email and your password will remain unchanged.\n`
      };

      transporter.sendMail(mailOptions, (error) => {
        if (error) {
          console.log(error);
          return res.render('forgot-password', { error: 'An error occurred while sending the email. Please try again.' });
        }
        res.render('forgot-password', { message: 'An email has been sent to ' + user.email + ' with further instructions.' });
      });
    });
  });
});

app.get('/reset-password/:token', (req, res) => {
  const { token } = req.params;
  db.get('SELECT * FROM users WHERE reset_token = ? AND reset_token_expires > ?', 
    [token, new Date().toISOString()], (err, user) => {
    if (err || !user) {
      return res.render('reset-password', { error: 'Password reset token is invalid or has expired.' });
    }
    res.render('reset-password', { token });
  });
});

app.post('/reset-password', (req, res) => {
  const { token, password, confirmPassword } = req.body;

  if (password !== confirmPassword) {
    return res.render('reset-password', { token, error: 'Passwords do not match.' });
  }

  db.get('SELECT * FROM users WHERE reset_token = ? AND reset_token_expires > ?', 
    [token, new Date().toISOString()], async (err, user) => {
    if (err || !user) {
      return res.render('reset-password', { error: 'Password reset token is invalid or has expired.' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    db.run('UPDATE users SET password = ?, reset_token = NULL, reset_token_expires = NULL WHERE id = ?', 
      [hashedPassword, user.id], (err) => {
      if (err) {
        console.error(err);
        return res.render('reset-password', { error: 'An error occurred. Please try again.' });
      }

      res.redirect('/login');
    });
  });
});

// Add the new route for the analytics page
app.get('/analytics', (req, res) => {
  if (!req.user) {
    return res.redirect('/login');
  }
  res.render('analytics', { user: req.user });
});

// Add the new API route for fetching analytics data
app.get('/api/analytics', async (req, res) => {
  if (!req.user) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  try {
    const totalClicks = await getTotalClicks(req.user.id);
    const totalUrls = await getTotalUrls(req.user.id);
    const averageCTR = totalUrls > 0 ? totalClicks / totalUrls : 0;
    const ctrOverTime = await getCTROverTime(req.user.id);
    const geoDistribution = await getGeoDistribution(req.user.id);
    const deviceStats = await getDeviceStats(req.user.id);
    const browserStats = await getBrowserStats(req.user.id);

    res.json({
      totalClicks,
      totalUrls,
      averageCTR,
      ctrOverTime,
      geoDistribution,
      deviceStats,
      browserStats
    });
  } catch (error) {
    console.error('Error fetching analytics data:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/:code', async (req, res) => {
  // make sure we're using the latest data
  db.get('PRAGMA read_uncommitted = true');
  const { code } = req.params;
  log('Accessing URL', { code });

  try {
    const url = await new Promise((resolve, reject) => {
      db.get('SELECT * FROM urls WHERE short_code = ? OR custom_alias = ?', [code, code], (err, row) => {
        if (err) reject(err);
        else resolve(row);
      });
    });

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

    const ip = req.ip;
    log('Client IP', { ip });

    const response = await axios.get(`http://ip-api.com/json/${ip}`);
    const country = response.data.countryCode;
    log('Country detected', { country });

    if (url.whitelist_mode) {
      const allowedCountries = url.allowed_countries ? url.allowed_countries.split(',') : [];
      log('Whitelist mode', { allowedCountries });
      if (!allowedCountries.includes(country)) {
        log('Access denied: country not in whitelist', { country });
        return res.status(403).render('access-denied');
      }
    } else {
      const blockedCountries = url.blocked_countries ? url.blocked_countries.split(',') : [];
      log('Blacklist mode', { blockedCountries });
      if (blockedCountries.includes(country)) {
        log('Access denied: country in blocklist', { country });
        return res.status(403).render('access-denied');
      }
    }

    const clickCount = await new Promise((resolve, reject) => {
      db.get('SELECT COUNT(*) as count FROM clicks WHERE url_id = ?', [url.id], (err, row) => {
        if (err) reject(err);
        else resolve(row.count);
      });
    });

    log('Current click count', { clickCount, maxUses: url.max_uses });

    if (url.max_uses !== null && url.max_uses > 0 && clickCount >= url.max_uses) {
      log('Max uses reached', { clickCount, maxUses: url.max_uses });
      return res.status(410).render('max-uses-reached');
    }

    const userAgent = req.headers['user-agent'];
    await new Promise((resolve, reject) => {
      db.run('INSERT INTO clicks (url_id, country, user_agent) VALUES (?, ?, ?)', [url.id, country, userAgent], (err) => {
        if (err) reject(err);
        else resolve();
      });
    });

    log('Click recorded', { urlId: url.id, country });
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
    const url = await new Promise((resolve, reject) => {
      db.get('SELECT * FROM urls WHERE short_code = ? OR custom_alias = ?', [code, code], (err, row) => {
        if (err) reject(err);
        else resolve(row);
      });
    });

    if (!url) {
      return res.status(404).json({ error: 'URL not found' });
    }

    // Check the number of failed attempts in the last 5 minutes
    const fiveMinutesAgo = new Date(Date.now() - 5 * 60 * 1000).toISOString();
    const failedAttempts = await new Promise((resolve, reject) => {
      db.get('SELECT COUNT(*) as count FROM failed_attempts WHERE url_id = ? AND ip_address = ? AND attempted_at > ?', 
        [url.id, ip, fiveMinutesAgo], (err, row) => {
        if (err) reject(err);
        else resolve(row.count);
      });
    });

    if (failedAttempts >= 5) {
      return res.status(429).json({ error: 'Too many failed attempts. Please try again later.' });
    }

    if (password !== url.password) {
      // Record failed attempt
      await new Promise((resolve, reject) => {
        db.run('INSERT INTO failed_attempts (url_id, ip_address) VALUES (?, ?)', [url.id, ip], (err) => {
          if (err) reject(err);
          else resolve();
        });
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

app.get('/stats/:code', (req, res) => {
  if (!req.user) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const { code } = req.params;
  db.get('SELECT * FROM urls WHERE (short_code = ? OR custom_alias = ?) AND user_id = ?', [code, code, req.user.id], (err, url) => {
    if (err || !url) {
      return res.status(404).json({ error: 'URL not found' });
    }

    db.all('SELECT * FROM clicks WHERE url_id = ?', [url.id], (err, clicks) => {
      if (err) {
        console.error(err);
        return res.status(500).json({ error: 'Error fetching click statistics' });
      }

      db.get('SELECT COUNT(*) as failed_attempts FROM failed_attempts WHERE url_id = ?', [url.id], (err, failedAttempts) => {
        if (err) {
          console.error(err);
          return res.status(500).json({ error: 'Error fetching failed attempts' });
        }
        res.json({ url, clicks, failedAttempts: failedAttempts.failed_attempts });
      });
    });
  });
});

app.get('/url/:code', (req, res) => {
  if (!req.user) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const { code } = req.params;
  db.get('SELECT * FROM urls WHERE (short_code = ? OR custom_alias = ?) AND user_id = ?', [code, code, req.user.id], (err, url) => {
    if (err || !url) {
      return res.status(404).json({ error: 'URL not found' });
    }
    res.json(url);
  });
});

app.put('/url/:code', (req, res) => {
  if (!req.user) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const { code } = req.params;
  const { maxUses, autoDeleteAt, whitelistMode, allowedCountries, blockedCountries, password } = req.body;

  // If autoDeleteAt is an empty string, set it to NULL in the database
  const autoDeleteAtValue = autoDeleteAt === '' ? null : autoDeleteAt;

  db.run(
    'UPDATE urls SET max_uses = ?, auto_delete_at = ?, whitelist_mode = ?, allowed_countries = ?, blocked_countries = ?, password = ? WHERE (short_code = ? OR custom_alias = ?) AND user_id = ?',
    [maxUses, autoDeleteAtValue, whitelistMode, allowedCountries, blockedCountries, password, code, code, req.user.id],
    function(err) {
      if (err) {
        console.error(err);
        return res.status(500).json({ error: 'Error updating URL' });
      }
      if (this.changes === 0) {
        return res.status(404).json({ error: 'URL not found' });
      }
      res.json({ message: 'URL updated successfully' });
    }
  );
});

app.delete('/url/:code', (req, res) => {
  if (!req.user) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const { code } = req.params;

  // Start a transaction
  db.serialize(() => {
    db.run('BEGIN TRANSACTION');

    // First, get the URL id
    db.get('SELECT id FROM urls WHERE (short_code = ? OR custom_alias = ?) AND user_id = ?', [code, code, req.user.id], (err, url) => {
      if (err) {
        db.run('ROLLBACK');
        console.error(err);
        return res.status(500).json({ error: 'Error finding URL' });
      }

      if (!url) {
        db.run('ROLLBACK');
        return res.status(404).json({ error: 'URL not found' });
      }

      // Delete associated clicks
      db.run('DELETE FROM clicks WHERE url_id = ?', [url.id], (err) => {
        if (err) {
          db.run('ROLLBACK');
          console.error(err);
          return res.status(500).json({ error: 'Error deleting associated clicks' });
        }

        // Delete associated failed attempts
        db.run('DELETE FROM failed_attempts WHERE url_id = ?', [url.id], (err) => {
          if (err) {
            db.run('ROLLBACK');
            console.error(err);
            return res.status(500).json({ error: 'Error deleting associated failed attempts' });
          }

          // Now delete the URL
          db.run('DELETE FROM urls WHERE id = ?', [url.id], function(err) {
            if (err) {
              db.run('ROLLBACK');
              console.error(err);
              return res.status(500).json({ error: 'Error deleting URL' });
            }

            db.run('COMMIT');
            res.json({ message: 'URL and associated data deleted successfully' });
          });
        });
      });
    });
  });
});

app.get('/find/:code', (req, res) => {
  const { code } = req.params;
  db.get('SELECT * FROM urls WHERE short_code = ? OR custom_alias = ?', [code, code], (err, url) => {
    if (err || !url) {
      return res.status(404).json({ error: 'URL not found' });
    }
    // construct the full URL
    const fullUrl = `${req.protocol}://${req.get('host')}/${url.short_code}`;
    res.json({ fullUrl });
  });
});

// Debug route
app.get('/debug/:code', (req, res) => {
  const { code } = req.params;
  db.get('SELECT * FROM urls WHERE short_code = ? OR custom_alias = ?', [code, code], (err, url) => {
    if (err || !url) {
      return res.status(404).json({ error: 'URL not found' });
    }
    db.get('SELECT COUNT(*) as click_count FROM clicks WHERE url_id = ?', [url.id], (err, result) => {
      if (err) {
        return res.status(500).json({ error: 'Error fetching click count' });
      }
      db.get('SELECT COUNT(*) as failed_attempts FROM failed_attempts WHERE url_id = ?', [url.id], (err, failedAttempts) => {
        if (err) {
          return res.status(500).json({ error: 'Error fetching failed attempts' });
        }
        res.json({ url, click_count: result.click_count, failed_attempts: failedAttempts.failed_attempts });
      });
    });
  });
});

// Add this new route for generating QR codes
app.get('/qr/:code', async (req, res) => {
  if (!req.user) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const { code } = req.params;
  
  try {
    const url = await new Promise((resolve, reject) => {
      db.get('SELECT * FROM urls WHERE (short_code = ? OR custom_alias = ?) AND user_id = ?', [code, code, req.user.id], (err, row) => {
        if (err) reject(err);
        else resolve(row);
      });
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
  return new Promise((resolve, reject) => {
    db.get('SELECT COUNT(*) as count FROM clicks WHERE url_id IN (SELECT id FROM urls WHERE user_id = ?)', [userId], (err, row) => {
      if (err) reject(err);
      else resolve(row.count);
    });
  });
}

async function getTotalUrls(userId) {
  return new Promise((resolve, reject) => {
    db.get('SELECT COUNT(*) as count FROM urls WHERE user_id = ?', [userId], (err, row) => {
      if (err) reject(err);
      else resolve(row.count);
    });
  });
}

async function getCTROverTime(userId) {
  return new Promise((resolve, reject) => {
    db.all(`
      SELECT DATE(clicks.clicked_at) as date, COUNT(*) as clicks, COUNT(DISTINCT urls.id) as urls
      FROM clicks
      JOIN urls ON clicks.url_id = urls.id
      WHERE urls.user_id = ?
      GROUP BY DATE(clicks.clicked_at)
      ORDER BY date
    `, [userId], (err, rows) => {
      if (err) reject(err);
      else {
        const ctrData = rows.map(row => ({
          date: row.date,
          ctr: row.urls > 0 ? row.clicks / row.urls : 0
        }));
        resolve(ctrData);
      }
    });
  });
}

async function getGeoDistribution(userId) {
  return new Promise((resolve, reject) => {
    db.all(`
      SELECT clicks.country, COUNT(*) as count
      FROM clicks
      JOIN urls ON clicks.url_id = urls.id
      WHERE urls.user_id = ?
      GROUP BY clicks.country
    `, [userId], (err, rows) => {
      if (err) reject(err);
      else {
        const geoData = {};
        rows.forEach(row => {
          const geo = geoip.lookup(row.country);
          if (geo) {
            const key = `${geo.ll[0]},${geo.ll[1]}`;
            geoData[key] = (geoData[key] || 0) + row.count;
          }
        });
        resolve(geoData);
      }
    });
  });
}

async function getDeviceStats(userId) {
  return new Promise((resolve, reject) => {
    db.all(`
      SELECT clicks.user_agent, COUNT(*) as count
      FROM clicks
      JOIN urls ON clicks.url_id = urls.id
      WHERE urls.user_id = ?
    `, [userId], (err, rows) => {
      if (err) reject(err);
      else {
        const deviceStats = {
          Desktop: 0,
          Mobile: 0,
          Tablet: 0,
          Other: 0
        };
        rows.forEach(row => {
          const agent = useragent.parse(row.user_agent);
          if (agent.isDesktop) deviceStats.Desktop += row.count;
          else if (agent.isMobile) deviceStats.Mobile += row.count;
          else if (agent.isTablet) deviceStats.Tablet += row.count;
          else deviceStats.Other += row.count;
        });
        resolve(deviceStats);
      }
    });
  });
}

async function getBrowserStats(userId) {
  return new Promise((resolve, reject) => {
    db.all(`
      SELECT clicks.user_agent, COUNT(*) as count
      FROM clicks
      JOIN urls ON clicks.url_id = urls.id
      WHERE urls.user_id = ?
    `, [userId], (err, rows) => {
      if (err) reject(err);
      else {
        const browserStats = {};
        rows.forEach(row => {
          const agent = useragent.parse(row.user_agent);
          const browser = agent.browser;
          browserStats[browser] = (browserStats[browser] || 0) + row.count;
        });
        resolve(browserStats);
      }
    });
  });
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
process.on('SIGINT', () => {
  console.log('Closing database connection...');
  db.close((err) => {
    if (err) {
      console.error(err.message);
    }
    console.log('Database connection closed.');
    process.exit(0);
  });
});