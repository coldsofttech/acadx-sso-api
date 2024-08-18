require('dotenv').config();

const express = require('express');
const rateLimit = require('express-rate-limit');
const passport = require('passport');
const GitHubStrategy = require('passport-github2').Strategy;

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
    new GitHubStrategy(
        {
            clientID: process.env.GITHUB_CLIENT_ID,
            clientSecret: process.env.GITHUB_CLIENT_SECRET,
            callbackURL: `${process.env.DOMAIN}/auth/github/callback`,
        },
        (accessToken, refreshToken, profile, done) => {
            return done(null, profile);
        }
    )
);

const router = express.Router();

router.get(
    '/auth/github',
    passport.authenticate('github', { scope: [ 'user:email' ]})
);

router.get(
    '/auth/github/callback',
    passport.authenticate('github', { failureRedirect: '/' }),
    (req, res) => {
        res.redirect(process.env.REDIRECT_URL);
    }
);

router.get(
    '/auth/github/logout',
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
    '/auth/github/user',
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
