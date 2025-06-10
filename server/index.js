const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const dotenv = require('dotenv');
const { verifyEmail, verifyPhone } = require('./services/verificationService');
const VerificationHistory = require('./models/VerificationHistory');

// Load environment variables
dotenv.config();

const app = express();

// Middleware
app.use(cors());
app.use(express.json());

// MongoDB Connection
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/verification-app')
  .then(() => console.log('Connected to MongoDB'))
  .catch(err => console.error('MongoDB connection error:', err));

// Basic route
app.get('/', (req, res) => {
  res.json({ message: 'Welcome to the Verification API' });
});

// Email verification route
app.post('/api/verify/email', async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) {
      return res.status(400).json({
        success: false,
        message: 'Email is required'
      });
    }

    const result = await verifyEmail(email);
    
    // Save to history
    await VerificationHistory.create({
      type: 'email',
      value: email,
      result: result,
      riskScore: result.riskScore || 0,
      status: result.success ? 'success' : 'error'
    });

    res.json(result);
  } catch (error) {
    console.error('Email verification error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Error verifying email' 
    });
  }
});

// Phone verification route
app.post('/api/verify/phone', async (req, res) => {
  try {
    const { phone } = req.body;
    if (!phone) {
      return res.status(400).json({
        success: false,
        message: 'Phone number is required'
      });
    }

    const result = await verifyPhone(phone);
    
    // Save to history
    await VerificationHistory.create({
      type: 'phone',
      value: phone,
      result: result,
      riskScore: result.riskScore || 0,
      status: result.success ? 'success' : 'error'
    });

    res.json(result);
  } catch (error) {
    console.error('Phone verification error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Error verifying phone' 
    });
  }
});

// Get verification history
app.get('/api/history', async (req, res) => {
  try {
    const history = await VerificationHistory.find()
      .sort({ timestamp: -1 })
      .limit(50);
    res.json(history);
  } catch (error) {
    console.error('Error fetching history:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Error fetching verification history' 
    });
  }
});

// Start server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
}); 