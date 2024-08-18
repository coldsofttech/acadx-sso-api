require('dotenv').config();

const express = require('express');
const rateLimit = require('express-rate-limit');
const passport = require('passport');
const LinkedInStrategy = require('passport-linkedin-oauth2').Strategy;

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
    new LinkedInStrategy(
        {
            clientID: process.env.LINKEDIN_CLIENT_ID,
            clientSecret: process.env.LINKEDIN_CLIENT_SECRET,
            callbackURL: '/auth/linkedin/callback',
            scope: ['r_emailaddress', 'r_liteprofile']
        },
        (accessToken, refreshToken, profile, done) => {
            return done(null, profile);
        }
    )
);

const router = express.Router();

router.get(
    '/auth/linkedin',
    passport.authenticate('linkedin', { state: true })
);

router.get(
    '/auth/linkedin/callback',
    passport.authenticate('linkedin', { failureRedirect: '/' }),
    (req, res) => {
        res.redirect(process.env.REDIRECT_URL);
    }
);

router.get(
    '/auth/linkedin/logout',
    (req, res) => {
        if (err) {
            return next(err);
        }
        req.session = null
        res.redirect('/')
    }
);

router.get(
    '/auth/linkedin/user',
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
