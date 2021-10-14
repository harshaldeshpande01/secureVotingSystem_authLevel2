const {check, validationResult} = require('express-validator');

exports.sanitizeSendOTP = [
    check('phone')
        .isLength({ min: 10 })
        .isLength({ max: 12 })
        .not()
        .isEmpty()
        .trim()
        .escape(),
    (req, res, next) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(422).send('Invalid input');
        }
        next();
    },
];

exports.sanitizeVerifyOTP = [
    check('phone')
        .isLength({ min: 10 })
        .isLength({ max: 12 })
        .not()
        .isEmpty()
        .trim()
        .escape(),
    check('hash')
        .not()
        .isEmpty()
        .trim(),
    check('otp')
        .isLength({ min: 6 })
        .isLength({ max: 6 })
        .isNumeric()
        .not()
        .isEmpty()
        .trim()
        .escape(),
    (req, res, next) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(422).send('Invalid input');
        }
        next();
    },
];

