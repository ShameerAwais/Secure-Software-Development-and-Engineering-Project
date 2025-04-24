const mongoose = require('mongoose');

const URLHistorySchema = new mongoose.Schema({
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  url: {
    type: String,
    required: true
  },
  result: {
    isSafe: Boolean,
    category: String,
    score: Number,
    details: Object
  },
  timestamp: {
    type: Date,
    default: Date.now
  },
  userAction: {
    type: String,
    enum: ['proceeded', 'blocked', 'ignored', 'reported'],
    default: 'proceeded'
  },
  device: {
    type: String
  }
});

// Index for faster querying by user
URLHistorySchema.index({ user: 1, timestamp: -1 });

const URLHistory = mongoose.model('URLHistory', URLHistorySchema);

module.exports = URLHistory;