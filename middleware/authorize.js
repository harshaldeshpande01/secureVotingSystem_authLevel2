const jwt = require("jsonwebtoken");

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
    const decoded = jwt.verify(token, process.env.JWT_AUTH_LEVEL1);
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
