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

router.post('/sendOTP', sendLimiter, authorizeRequest, sanitizeSendOTP, sendOTP)

router.post('/verifyOTP', verifyLimiter, authorizeRequest, sanitizeVerifyOTP, verifyOTP)

module.exports = router