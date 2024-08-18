require('dotenv').config();

const express = require('express');
const rateLimit = require('express-rate-limit');
const passport = require('passport');
const OIDCStrategy = require('passport-azure-ad').OIDCStrategy;

const limiter = rateLimit({
    windowMs: process.env.RATE_LIMIT_WINDOWMS,
    max: process.env.RATE_LIMIT_MAX_IPS,
    message: process.env.RATE_LIMIT_ERROR_MESSAGE
});

const azureADConfig = {
    identityMetadata: `https://login.microsoftonline.com/${process.env.MICROSOFT_TENANT_ID}/v2.0/.well-known/openid-configuration`,
    clientID: process.env.MICROSOFT_CLIENT_ID,
    clientSecret: process.env.MICROSOFT_CLIENT_SECRET,
    redirectUrl: `${process.env.DOMAIN}/auth/microsoft/callback`,
    allowHttpForRedirectUrl: process.env.ENVIRONMENT != 'prod',
    responseType: 'code',
    responseMode: 'query',
    scope: ['profile', 'offline_access', 'email'],
    loggingLevel: 'info'
}

passport.serializeUser((user, done) => {
    done(null, user);
});

passport.deserializeUser((user, done) => {
    done(null, user);
});

passport.use(
    new OIDCStrategy(
        azureADConfig,
        (iss, sub, profile, accessToken, refreshToken, done) => {
            return done(null, profile);
        }
    )
);

const router = express.Router();

router.get(
    '/auth/microsoft',
    passport.authenticate('azuread-openidconnect', { failureRedirect: '/' }),
    (req, res) => {
        res.redirect(process.env.REDIRECT_URL);
    }
);

router.get(
    '/auth/microsoft/callback',
    passport.authenticate('azuread-openidconnect', { failureRedirect: '/' }),
    (req, res) => {
        res.redirect(process.env.REDIRECT_URL);
    }
);

router.get(
    '/auth/microsoft/logout',
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
    '/auth/microsoft/user',
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
