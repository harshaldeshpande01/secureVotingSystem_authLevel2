const express = require('express')
const router = express.Router()

const { 
	authorizeRequest 
} = require("../middleware/authorize");

const {
	verifyLimiter,
	sendLimiter
} = require("../middleware/rateLImiters");

const { 
	sanitizeSendOTP, 
	sanitizeVerifyOTP 
} = require('../middleware/sanitizers');

const {
    sendOTP,
    verifyOTP
} = require('../Controllers/OTP.Controller')

router.post('/sendOTP', sendLimiter, sanitizeSendOTP, sendOTP)

router.post('/verifyOTP', verifyLimiter, sanitizeVerifyOTP, verifyOTP)

module.exports = router