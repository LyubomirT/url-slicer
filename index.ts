import express from 'express';
import path from 'path';

const app = express();
const port = 3000;

// Serve static files from the "public" directory
app.use(express.static(path.join(__dirname, 'public')));

var storedURLs: string[] = [];
 
function addURL(url: string) {
    storedURLs.push(url);
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
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(port, () => {
    console.log(`Server started at http://localhost:${port}`);
});