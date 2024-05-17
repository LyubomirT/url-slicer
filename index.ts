import express from 'express';
import path from 'path';
import { randomInt } from 'crypto';
import bodyParser from 'body-parser';
import passport from 'passport';
import LocalStrategy from 'passport-local';
import session from 'express-session';
import fs from 'fs';
import crypto from 'crypto';

interface User {
    id: string;
    username: string;
    password: string;
    token: string;
}

let users: User[] = [];

const app = express();
const port = 3000;

app.use(express.static(path.join(__dirname, 'public')));
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());

// Passport settings
app.use(
    session({
        secret: 'your-secret-key',
        resave: false,
        saveUninitialized: false,
    })
);
app.use(passport.initialize());
app.use(passport.session());

passport.use(
    new LocalStrategy((username, password, done) => {
        const user = users.find((u) => u.username === username && u.password === password);
        if (user) {
            return done(null, user);
        } else {
            return done(null, false, { message: 'Invalid credentials' });
        }
    })
);

passport.serializeUser((user: Express.User, done) => {
    done(null, (user as User).id);
});

passport.deserializeUser((id: string, done) => {
    const user = users.find((u) => u.id === id);
    done(null, user ? user : false);
});

function generateToken(): string {
    return crypto.randomBytes(16).toString('hex');
}

function generateUserID(): string {
    return crypto.randomBytes(4).toString('hex');
}

// Routes for Auth
app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.get('/signup', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'signup.html'));
});

app.post(
    '/login',
    passport.authenticate('local', {
        successRedirect: '/tokendownload',
        failureRedirect: '/login',
    })
);

app.post('/signup', (req, res) => {
    const { username, password } = req.body;
    const token = generateToken();
    const user = { id: generateUserID(), username, password, token };
    users.push(user);
    res.setHeader('Content-disposition', 'attachment; filename=token.txt');
    res.set('Content-Type', 'text/plain');
    res.send(`Your Recovery Token:\n\n${token}`);
});

app.get('/tokendownload', (req, res) => {
    if (req.isAuthenticated()) {
        const user = users.find((u) => u.id === (req.user as User).id);
        if (user) {
            res.sendFile(path.join(__dirname, 'public', 'tokendownload.html'));
        }
    } else {
        res.redirect('/login');
    }
});

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'interface.html'));
});

// URL Shortener Logic
interface StoredURL {
    url: string;
    expiry: number | null;
    maxUses: number | null;
    uses: number;
}

var storedURLs: { [key: string]: StoredURL } = {};

function generateID(): string {
    const alphabet: string = 'abcdefghijklmnopqrstuvwxyz';
    const numbers: string = '0123456789';
    const characters: string = alphabet + alphabet.toUpperCase() + numbers;
    let id: string = '';
    for (let i = 0; i < 6; i++) {
        id += characters[randomInt(0, characters.length)];
    }
    return id;
}

function addURL(url: string, expiry: number | null, maxUses: number | null): string {
    const id = generateID();
    console.log(`Shortening ${url} to ${id}`);
    const shortURL = `http://localhost:${port}/${id}`;
    storedURLs[id] = { url, expiry, maxUses, uses: 0 };
    return shortURL;
}

function isValidURL(url: string): boolean {
    try {
        new URL(url);
        return true;
    } catch (error) {
        return false;
    }
}

app.post('/api/shorten', (req, res) => {
    const { url, expiry, maxUses } = req.body;
    if (!url) {
        res.status(400).send('Missing URL parameter');
        console.log('Missing URL parameter');
        return;
    }
    const expiryTime = expiry ? Date.now() + expiry * 1000 : null;
    const shortURL = addURL(url, expiryTime, maxUses);
    res.status(200).send({ url: shortURL });
});

app.get('/:id', (req, res) => {
    const id = req.params.id as string;
    const record = storedURLs[id];

    if (record) {
        const { url, expiry, maxUses, uses } = record;

        if (expiry && Date.now() > expiry) {
            delete storedURLs[id];
            res.status(404).send('URL has expired');
        } else if (maxUses && uses >= maxUses) {
            delete storedURLs[id];
            res.status(404).send('URL has exceeded maximum uses');
        } else {
            record.uses += 1;
            res.redirect(url);
        }
    } else {
        res.status(404).send('URL not found');
    }
});

app.listen(port, () => {
    console.log(`Server started at http://localhost:${port}`);
});