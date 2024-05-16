import express from 'express';
import path from 'path';
/* random number generator for picking random letters */
import { randomInt } from 'crypto';
import bodyParser from 'body-parser';

const app = express();
const port = 3000;

// Serve static files from the "public" directory
app.use(express.static(path.join(__dirname, 'public')));

var jsonParser = bodyParser.json();

// create application/x-www-form-urlencoded parser
var urlencodedParser = bodyParser.urlencoded({ extended: false })

var storedURLs: string[] = [];

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
 
function addURL(url: string) {
    const id = generateID();
    console.log(`Shortening ${url} to ${id}`);
    var shortURL = `http://localhost:${port}/${id}`;
    storedURLs.push(shortURL);
    return shortURL;
}

function isValidURL(url: string) {
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
    var url = req.body.url as string;
    if (!url) {
        res.status(400).send('Missing URL parameter');
        console.log('Missing URL parameter');
        return;
    }
    var url_ = addURL(url);
    res.status(200).send({ url: url_ });
});



app.listen(port, () => {
    console.log(`Server started at http://localhost:${port}`);
});