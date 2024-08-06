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
const axios = require('axios'); // Add this line to import axios
dotenv.config();

const app = express();
const port = process.env.PORT || 3000;

// Database setup
const db = new sqlite3.Database('./database.sqlite');

// Create users table if not exists
db.run(`CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT UNIQUE,
  password TEXT,
  verified BOOLEAN,
  verification_token TEXT
)`);

// Create urls table if not exists
db.run(`CREATE TABLE IF NOT EXISTS urls (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER,
  original_url TEXT,
  short_code TEXT UNIQUE,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  max_uses INTEGER,
  auto_delete_at DATETIME,
  whitelist_mode BOOLEAN,
  allowed_countries TEXT,
  blocked_countries TEXT,
  FOREIGN KEY (user_id) REFERENCES users (id)
)`);

// Create clicks table if not exists
db.run(`CREATE TABLE IF NOT EXISTS clicks (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  url_id INTEGER,
  clicked_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  country TEXT,
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
  secret: 'your-secret-key',
  resave: false,
  saveUninitialized: false
}));
app.use(passport.initialize());
app.use(passport.session());

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

  const { originalUrl, maxUses, autoDeleteAt, whitelistMode, allowedCountries, blockedCountries } = req.body;
  const shortCode = shortid.generate();

  db.run(
    'INSERT INTO urls (user_id, original_url, short_code, max_uses, auto_delete_at, whitelist_mode, allowed_countries, blocked_countries) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
    [req.user.id, originalUrl, shortCode, maxUses, autoDeleteAt, whitelistMode, allowedCountries, blockedCountries],
    function(err) {
      if (err) {
        console.error(err);
        return res.status(500).json({ error: 'Error creating shortened URL' });
      }
      res.json({ shortCode: shortCode });
    }
  );
});

app.get('/:shortCode', async (req, res) => {
  const { shortCode } = req.params;
  db.get('SELECT * FROM urls WHERE short_code = ?', [shortCode], async (err, url) => {
    if (err || !url) {
      return res.status(404).send('URL not found');
    }

    const ip = req.ip;
    console.log('IP:', ip);
    try {
      const response = await axios.get(`http://ip-api.com/json/${ip}`);
      console.log(response.data);
      const country = response.data.countryCode;

      if (url.whitelist_mode) {
        const allowedCountries = url.allowed_countries ? url.allowed_countries.split(',') : [];
        if (!allowedCountries.includes(country)) {
          return res.status(403).send('Access denied from your country');
        }
      } else {
        const blockedCountries = url.blocked_countries ? url.blocked_countries.split(',') : [];
        if (blockedCountries.includes(country)) {
          return res.status(403).send('Access denied from your country');
        }
      }

      if (url.max_uses !== null) {
        db.get('SELECT COUNT(*) as click_count FROM clicks WHERE url_id = ?', [url.id], (err, result) => {
          if (err) {
            console.error(err);
            return res.status(500).send('Error checking click count');
          }
          if (result.click_count >= url.max_uses) {
            return res.status(410).send('This link has reached its maximum number of uses');
          }
          recordClickAndRedirect(url, country, res);
        });
      } else {
        recordClickAndRedirect(url, country, res);
      }
    } catch (error) {
      console.error('Error fetching country information:', error);
      return res.status(500).send('Error processing your request');
    }
  });
});

function recordClickAndRedirect(url, country, res) {
  db.run('INSERT INTO clicks (url_id, country) VALUES (?, ?)', [url.id, country], (err) => {
    if (err) {
      console.error(err);
    }
    res.redirect(url.original_url);
  });
}

app.get('/stats/:shortCode', (req, res) => {
  if (!req.user) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const { shortCode } = req.params;
  db.get('SELECT * FROM urls WHERE short_code = ? AND user_id = ?', [shortCode, req.user.id], (err, url) => {
    if (err || !url) {
      return res.status(404).json({ error: 'URL not found' });
    }

    db.all('SELECT * FROM clicks WHERE url_id = ?', [url.id], (err, clicks) => {
      if (err) {
        console.error(err);
        return res.status(500).json({ error: 'Error fetching click statistics' });
      }
      res.json({ url, clicks });
    });
  });
});

app.get('/url/:shortCode', (req, res) => {
  if (!req.user) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const { shortCode } = req.params;
  db.get('SELECT * FROM urls WHERE short_code = ? AND user_id = ?', [shortCode, req.user.id], (err, url) => {
    if (err || !url) {
      return res.status(404).json({ error: 'URL not found' });
    }
    res.json(url);
  });
});

app.put('/url/:shortCode', (req, res) => {
  if (!req.user) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const { shortCode } = req.params;
  const { maxUses, autoDeleteAt, whitelistMode, allowedCountries, blockedCountries } = req.body;

  db.run(
    'UPDATE urls SET max_uses = ?, auto_delete_at = ?, whitelist_mode = ?, allowed_countries = ?, blocked_countries = ? WHERE short_code = ? AND user_id = ?',
    [maxUses, autoDeleteAt, whitelistMode, allowedCountries, blockedCountries, shortCode, req.user.id],
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

app.delete('/url/:shortCode', (req, res) => {
  if (!req.user) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const { shortCode } = req.params;

  db.run('DELETE FROM urls WHERE short_code = ? AND user_id = ?', [shortCode, req.user.id], function(err) {
    if (err) {
      console.error(err);
      return res.status(500).json({ error: 'Error deleting URL' });
    }
    if (this.changes === 0) {
      return res.status(404).json({ error: 'URL not found' });
    }
    res.json({ message: 'URL deleted successfully' });
  });
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});