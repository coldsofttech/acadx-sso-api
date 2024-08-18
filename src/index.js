require('dotenv').config();

const express = require('express');
const session = require('express-session');
const passport = require('passport');
const googleRoutes = require('./services/google/google');
const linkedInRoutes = require('./services/linkedin/linkedin');
const facebookRouters = require('./services/facebook/facebook');
const microsoftRouters = require('./services/microsoft/microsoft');
const port = process.env.PORT || 3002;

const app = express();

app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
    cookie: {
        secure: process.env.ENVIRONMENT === 'prod',
        httpOnly: true
    }
}));

app.use(passport.initialize());
app.use(passport.session());

app.use(googleRoutes);
app.use(linkedInRoutes);
app.use(facebookRouters);
app.use(microsoftRouters);

app.listen(port, () => {
    console.log(`AcadX SSO API running on http://localhost:${port}`)
});
