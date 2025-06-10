const mongoose = require('mongoose');

const verificationHistorySchema = new mongoose.Schema({
  type: {
    type: String,
    required: true,
    enum: ['email', 'phone']
  },
  value: {
    type: String,
    required: true
  },
  result: {
    type: Object,
    required: true
  },
  riskScore: {
    type: Number,
    required: true
  },
  status: {
    type: String,
    required: true,
    enum: ['success', 'error']
  },
  timestamp: {
    type: Date,
    default: Date.now
  }
});

module.exports = mongoose.model('VerificationHistory', verificationHistorySchema); 