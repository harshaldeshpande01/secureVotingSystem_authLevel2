const jwt = require("jsonwebtoken");
const fs = require('fs');

const JWT_PUBLIC_KEY=fs.readFileSync(__dirname + '/../jwtRS256_level1.key.pub', 'utf-8');

const verifyOptions = {
  expiresIn: '5min',
  algorithms: ["RS256"]
}

exports.authorizeRequest = async (req, res, next) => {
  let token;

  if (
    req.headers.authorization &&
    req.headers.authorization.startsWith("Bearer")
  ) {
    token = req.headers.authorization.split(" ")[1];
  }

  if (!token) {
    return res.status(401).send("Not authorized to access this router");
  }

  try {
    const decoded = jwt.verify(token, JWT_PUBLIC_KEY, verifyOptions);
    if(decoded) {
        req.email = decoded.email;
        next();
    }
    else {
      return res.status(401).send("Not authorized to access this router");
    }
  } catch (err) {
    return res.status(401).send("Not authorized to access this router");
  }
};
