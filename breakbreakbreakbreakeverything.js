require('dotenv').config();
const mongoose = require('mongoose');

// Connect to MongoDB
mongoose.connect(process.env.MongoURI)
  .then(() => console.log('Connected to MongoDB...'))
  .catch(err => {
    console.error('Could not connect to MongoDB...', err);
    process.exit(1);
  });

async function breakEverything() {
  try {
    // Get all collection names
    const collections = await mongoose.connection.db.listCollections().toArray();
    
    // Loop through all collections and delete all documents
    for (let collection of collections) {
      console.log(`Clearing collection: ${collection.name}`);
      await mongoose.connection.db.collection(collection.name).deleteMany({});
      console.log(`Collection ${collection.name} cleared.`);
    }

    console.log('All collections have been cleared. The database is now empty.');
  } catch (error) {
    console.error('An error occurred while clearing the database:', error);
  } finally {
    // Close the database connection
    await mongoose.connection.close();
    console.log('Database connection closed.');
  }
}

// Run the function
breakEverything().then(() => {
  console.log('Database cleaning process completed.');
  process.exit(0);
});

// Add a warning message
console.log('\x1b[31m%s\x1b[0m', `
WARNING: This script will delete ALL data in your database.
It's named because of a song reference,
but it will literally break everything in your database.
Make sure you have a backup before running this script.
To proceed, press any key. To cancel, press Ctrl+C.
`);

// Wait for user input before proceeding
process.stdin.setRawMode(true);
process.stdin.resume();
process.stdin.on('data', process.exit.bind(process, 0));