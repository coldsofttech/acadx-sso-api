require('dotenv').config();

const express = require('express');
const rateLimit = require('express-rate-limit');
const passport = require('passport');
const FacebookStrategy = require('passport-facebook').Strategy;

const limiter = rateLimit({
    windowMs: process.env.RATE_LIMIT_WINDOWMS,
    max: process.env.RATE_LIMIT_MAX_IPS,
    message: process.env.RATE_LIMIT_ERROR_MESSAGE
});

passport.serializeUser((user, done) => {
    done(null, user);
});

passport.deserializeUser((user, done) => {
    done(null, user);
});

passport.use(
    new FacebookStrategy(
        {
            clientID: process.env.FACEBOOK_CLIENT_ID,
            clientSecret: process.env.FACEBOOK_CLIENT_SECRET,
            callbackURL: '/auth/facebook/callback',
            profileFields: ['id', 'emails', 'name']
        },
        (accessToken, refreshToken, profile, done) => {
            return done(null, profile);
        }
    )
);

const router = express.Router();

router.get(
    '/auth/facebook',
    passport.authenticate('facebook', { scope: [ 'email' ]})
);

router.get(
    '/auth/facebook/callback',
    passport.authenticate('facebook', { failureRedirect: '/' }),
    (req, res) => {
        res.redirect(process.env.REDIRECT_URL);
    }
);

router.get(
    '/auth/facebook/logout',
    (req, res) => {
        req.logout();
        if (err) {
            return next(err);
        }
        req.session = null
        res.redirect('/')
    }
);

router.get(
    '/auth/facebook/user',
    limiter,
    (req, res) => {
        if (req.isAuthenticated()) {
            res.send(req.user);
        } else {
            res.status(401).send('Not authenticated');
        }
    }
);

module.exports = router;
