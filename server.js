require('dotenv').config();

const express = require('express');
const hpp = require('hpp');
const cors = require('cors')
const helmet = require('helmet');
const compression = require('compression'); 
const createError = require('http-errors');

const OTPRoutes = require('./Routes/OTP.Routes')

const app = express();

// Middleware
// Parse request
app.use(express.urlencoded({ extended: true, limit: "1kb" }));
app.use(express.json({ limit: "1kb" }));
app.use(hpp());

// Set headers and gzip response
app.use(cors());
app.use(helmet());
app.use(compression());

app.use('/api/authLevel2', OTPRoutes);


// Handle 404's
app.use(async (req, res, next) => {
  next(createError.NotFound())
})

app.use((err, req, res, next) => {
  res.status(err.status || 500)
  res.send({
    error: {
      status: err.status || 500,
      message: err.message,
    },
  })
})

app.listen(process.env.PORT || 9996);
