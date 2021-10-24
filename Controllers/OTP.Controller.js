const crypto = require('crypto');
const otpGenerator = require('otp-generator')
const jwt = require('jsonwebtoken')

const accountSid = process.env.ACCOUNT_SID;
const authToken = process.env.AUTH_TOKEN;
const smsKey = process.env.SMS_SECRET_KEY;
const client = require('twilio')(accountSid, authToken);

exports.sendOTP = (req, res, _next) => {
	const phone = req.body.phone;
	const otp = otpGenerator.generate(6, { alphabets: false, upperCase: false, specialChars: false });
	const ttl = 60 * 1000;
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
		// .then((_messages) => res.status(200).send({ phone, hash: fullHash }))
		// .catch((_err) => res.status(400).send("SMS could\'t be sent. Unverified phone number")
		// );
    res.status(200).send({ phone, hash: fullHash })
};

exports.verifyOTP = (req, res, _next) => {
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
		const accessToken = 
		jwt.sign(
			{ 
				email: req.email, 
				authLevel2: true 
			}, 
			process.env.LEVEL2_PRIVATE_KEY,
			{ 
				expiresIn: process.env.JWT_EXPIRE,
				algorithm: 'RS256'
			}
		);
		res.status(200).json({success: true, accessToken});
	} else {
		return res.status(400).send("Incorrect OTP");
	}
};
