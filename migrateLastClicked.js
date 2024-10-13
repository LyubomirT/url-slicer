const mongoose = require('mongoose');
const dotenv = require('dotenv');
const { Click } = require('./server.js');

dotenv.config();

// Connect to MongoDB
mongoose.connect(process.env.MongoURI)
  .then(() => console.log('Connected to MongoDB for migration...'))
  .catch(err => console.error('MongoDB connection error:', err));

// Check if the model is already compiled, and if not, define it
if (!mongoose.models.Url) {
  // Define Url schema with last_clicked_at
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
    password: String,
    last_clicked_at: { type: Date, default: null }
  });

  mongoose.model('Url', urlSchema);
}

const Url = mongoose.model('Url');  // Retrieve the model, whether it was just defined or already existed

async function migrateLastClicked() {
  try {
    const urls = await Url.find({ last_clicked_at: null });
    for (const url of urls) {
      const lastClick = await Click.findOne({ url_id: url._id }).sort({ clicked_at: -1 }).exec();
      if (lastClick) {
        url.last_clicked_at = lastClick.clicked_at;
        await url.save();
        console.log(`Updated URL ${url.short_code} with last_clicked_at: ${lastClick.clicked_at}`);
      }
    }
    console.log('Migration completed.');
  } catch (error) {
    console.error('Migration error:', error);
  } finally {
    mongoose.connection.close();
  }
}

migrateLastClicked();
