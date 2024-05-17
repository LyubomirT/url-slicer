import express from 'express';
import path from 'path';
import { randomInt } from 'crypto';
import bodyParser from 'body-parser';

const app = express();
const port = 3000;

app.use(express.static(path.join(__dirname, 'public')));
var jsonParser = bodyParser.json();
var urlencodedParser = bodyParser.urlencoded({ extended: false });

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

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'interface.html'));
});

app.post('/api/shorten', jsonParser, (req, res) => {
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
