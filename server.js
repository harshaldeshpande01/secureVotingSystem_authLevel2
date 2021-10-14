require('dotenv').config();

const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');

const { 
	authorizeRequest 
} = require("./middleware/authorize");

const { 
	sanitizeSendOTP, 
	sanitizeVerifyOTP 
} = require('./middleware/sanitizers');


// const JWT_REFRESH_LEVEL2 = process.env.JWT_REFRESH_LEVEL2
// let refreshTokens = [];
const JWT_AUTH_LEVEL2 = process.env.JWT_AUTH_LEVEL2
const accountSid = process.env.ACCOUNT_SID;
const authToken = process.env.AUTH_TOKEN;
const smsKey = process.env.SMS_SECRET_KEY;
const client = require('twilio')(accountSid, authToken);

const app = express();

app.use(express.json());
app.use(cors());


app.post('/sendOTP', sanitizeSendOTP, authorizeRequest, (req, res) => {
	const phone = req.body.phone;
	const otp = Math.floor(100000 + Math.random() * 900000);
	const ttl = 2 * 60 * 1000;
	const expires = Date.now() + ttl;
	const data = `${phone}.${otp}.${expires}`;
	const hash = crypto.createHmac('sha256', smsKey).update(data).digest('hex');
	const fullHash = `${hash}.${expires}`;

	client.messages
		.create({
			body: `Your One Time Login Password For Secure Voting System is ${otp}`,
			from: +13192532190,
			to: phone
		})
		.then((messages) => res.status(200).send({ phone, hash: fullHash }))
		.catch((err) => res.status(400).send("SMS could\'t be sent. Unverifird phone number")
		);
});

app.post('/verifyOTP', sanitizeVerifyOTP, authorizeRequest, (req, res) => {
	const phone = req.body.phone;
	const hash = req.body.hash;
	const otp = req.body.otp;
	if(!phone || !hash || !otp) {
		return res.status(400).send("Bad request");
	}
	let [ hashValue, expires ] = hash.split('.');

	let now = Date.now();
	if (now > parseInt(expires)) {
		return res.status(504).send("Timed out!");
	}
	let data = `${phone}.${otp}.${expires}`;
	let newCalculatedHash = crypto.createHmac('sha256', smsKey).update(data).digest('hex');
	if (newCalculatedHash === hashValue) {
		const accessToken = jwt.sign({ email: req.email, authLevel2: true }, JWT_AUTH_LEVEL2, { expiresIn: process.env.JWT_AUTH_EXPIRE });
		// const refreshToken = jwt.sign({ }, JWT_REFRESH_LEVEL2, { expiresIn: process.env.JWT_REFRESH_EXPIRE });
		// refreshTokens.push(refreshToken);
		res.status(200).json({success: true, accessToken});
	} else {
		return res.status(400).send("Incorrect OTP");
	}
});

// app.post('/refresh', (req, res) => {
// 	const refreshToken = req.body.refreshToken;
// 	if (!refreshToken) return res.status(403).send({ message: 'Refresh token not found, login again' });
// 	// if (!refreshTokens.includes(refreshToken))
// 	// 	return res.status(403).send({ message: 'Refresh token blocked, login again' });

// 	jwt.verify(refreshToken, JWT_REFRESH_LEVEL2, (err) => {
// 		if (!err) {
// 			const accessToken = jwt.sign({ }, JWT_AUTH_LEVEL2, {
// 				expiresIn: process.env.JWT_AUTH_EXPIRE
// 			});
// 			return res.status(200).json({success: true, refreshedToken: true, accessToken});
// 		} else {
// 			return res.status(403).send({
// 				success: false,
// 				msg: 'Invalid refresh token'
// 			});
// 		}
// 	});
// });

app.listen(process.env.PORT || 9996);
