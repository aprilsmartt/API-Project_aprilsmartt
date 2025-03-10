// backend/routes/api/session.js
const express = require('express');
const { Op } = require('sequelize');
const bcrypt = require('bcryptjs');

const { setTokenCookie, restoreUser } = require('../../utils/auth');
const { User } = require('../../db/models');

//! Validate the body of a request.
const { check } = require('express-validator');
const { handleValidationErrors } = require('../../utils/validation');


const router = express.Router();

//! Check to see whether or not `req.body.credential` and `req.body.password` are empty.
const validateLogin = [
  check('credential')
    .exists({ checkFalsy: true })
    .notEmpty()
    .withMessage('Please provide a valid email or username.'),
  check('password')
    .exists({ checkFalsy: true })
    .withMessage('Please provide a password.'),
  handleValidationErrors
];

// Log in
router.post(
  '/',
  validateLogin, //! Connects `POST /api/session` route to `validateLogin` middleware.
  async (req, res, next) => {
    const { credential, password } = req.body;

    //! Find the user by either username or email
    const user = await User.unscoped().findOne({
      where: {
        [Op.or]: {
          username: credential,
          email: credential
        }
      }
    });

    //! Check if user exists and password is correct
    if (!user || !bcrypt.compareSync(password, user.hashedPassword.toString())) {
      const err = new Error('Login failed');
      err.status = 401;
      err.title = 'Login failed';
      err.errors = { credential: 'The provided credentials were invalid.' };
      return next(err);
    }

    //! Create a safe user object (without hashedPassword)
    //! Update by ADDING firstName and lastName here
    const safeUser = {
      id: user.id,
      email: user.email,
      username: user.username,
      firstName: user.firstName,
      lastName: user.lastName
    };

    //! Set the JWT cookie
    await setTokenCookie(res, safeUser);

    //! Return the user information
    return res.json({
      user: safeUser
    });
  }
);

// Log out
router.delete(
  '/',
  (_req, res) => {
    res.clearCookie('token');
    return res.json({ message: 'success' });
  }
);

// Restore session user
router.get(
  '/',
  (req, res) => {
    const { user } = req;
    if (user) {
      //! Update by ADDING firstName and lastName here
      const safeUser = {
        id: user.id,
        email: user.email,
        username: user.username,
        firstName: user.firstName,
        lastName: user.lastName
      };
      return res.json({
        user: safeUser
      });
    } else return res.json({ user: null });
  }
);




module.exports = router;


