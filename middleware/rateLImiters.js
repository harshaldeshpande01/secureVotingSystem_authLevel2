const rateLimit = require("express-rate-limit");

exports.sendLimiter = rateLimit({
    windowMs: 5 * 60 * 1000, // 5 minute
    max: 2, // Start blocking after 2 requests
    message: "Too many OTP requests from this IP, please try again later",
    headers: true
});

exports.verifyLimiter = rateLimit({
    windowMs: 2 * 60 * 1000, // 1 minute
    max: 5, // Start blocking after 2 requests
    message: "Too many verify requests from this IP, please try again later",
    headers: true
});