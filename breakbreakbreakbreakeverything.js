const mongoose = require('mongoose');
const dotenv = require('dotenv');

dotenv.config();

// Connect to MongoDB
mongoose.connect(process.env.MongoURI)
  .then(() => console.log('Connected to MongoDB...'))
  .catch(err => console.error('Could not connect to MongoDB:', err));

var collections = [];

async function breakEverything() {
    console.log('🎵 BREAK, BREAK, BREAK, BREAK!!... BREAK EVERYTHING...');
    for (let collection of collections) {
        try {
            await mongoose.connection.db.collection(collection.name).deleteMany({});
            console.log(`Deleted all documents in collection ${collection.collectionName}`);
        } catch (err) {
            console.error(`Could not delete all documents in collection ${collection.collectionName}:`, err);
        }
    }
    console.log('Done breaking everything');
    process.exit(0);
}

// Get all collections
mongoose.connection.on('open', async () => {
    collections = await mongoose.connection.db.listCollections().toArray();
    breakEverything();
});