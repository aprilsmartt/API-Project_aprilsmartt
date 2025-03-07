const express = require('express');
require('express-async-errors');
const morgan = require('morgan');
const cors = require('cors');
const csurf = require('csurf');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');

//! Check if the environment is in production or not
const { environment } = require('./config');
const isProduction = environment === 'production';

const routes = require('./routes');

//! Initialize the Express application:
const app = express();

//! Use "morgan" middleware to log info about requests and responses
app.use(morgan('dev'));

//! Add the `cookie-parser` middleware for parsing cookies and the `express.json`middleware for parsing JSON bodies of requests with `Content-Type` of`"application/json"`.
app.use(cookieParser());
app.use(express.json());

//! Add several security middlewares:
// Security Middleware
if (!isProduction) {
    // enable cors only in development
    app.use(cors());
  }
  
  // helmet helps set a variety of headers to better secure your app
  app.use(
    helmet.crossOriginResourcePolicy({
      policy: "cross-origin"
    })
  );
  
  // Set the _csrf token and create req.csrfToken method
  app.use(
    csurf({
      cookie: {
        secure: isProduction,
        sameSite: isProduction && "Lax",
        httpOnly: true
      }
    })
  );
  

  app.use(routes); // Connect all the routes

  module.exports = app;
