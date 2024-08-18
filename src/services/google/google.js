const express = require('express');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;

passport.serializeUser((user, done) => {
    done(null, user);
});

passport.deserializeUser((user, done) => {
    done(null, user);
});

passport.use(
    new GoogleStrategy(
        {
            clientID: process.env.GOOGLE_CLIENT_ID,
            clientSecret: process.env.GOOGLE_CLIENT_SECRET,
            callbackURL: '/auth/google/callback',
        },
        (accessToken, refreshToken, profile, done) => {
            return done(null, profile);
        }
    )
);

const router = express.Router();

router.get(
    '/auth/google',
    passport.authenticate('google', { scope: [ 'profile', 'email' ]})
);

router.get(
    '/auth/google/callback',
    passport.authenticate('google', { failureRedirect: '/' }),
    (req, res) => {
        res.redirect(process.env.REDIRECT_URL);
    }
);

router.get(
    '/auth/google/logout',
    (req, res) => {
        if (err) {
            return next(err);
        }
        req.session = null
        res.redirect('/')
    }
);

router.get(
    '/auth/google/user',
    (req, res) => {
        if (req.isAuthenticated()) {
            res.send(req.user);
        } else {
            res.status(401).send('Not authenticated');
        }
    }
);

module.exports = router;
