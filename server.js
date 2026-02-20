require('dotenv').config();
const express = require('express');
const session = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const GitHubStrategy = require('passport-github2').Strategy;
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// Serve static frontend files (index.html, css, etc.)
app.use(express.static(path.join(__dirname)));

app.use(session({
  secret: process.env.SESSION_SECRET || 'change_this',
  resave: false,
  saveUninitialized: false,
}));

app.use(passport.initialize());
app.use(passport.session());

passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((obj, done) => done(null, obj));

// Google OAuth
passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: process.env.GOOGLE_CALLBACK_URL || 'http://localhost:3000/auth/google/callback'
}, (accessToken, refreshToken, profile, done) => {
  return done(null, { provider: 'google', profile, accessToken });
}));

// GitHub OAuth
passport.use(new GitHubStrategy({
  clientID: process.env.GITHUB_CLIENT_ID,
  clientSecret: process.env.GITHUB_CLIENT_SECRET,
  callbackURL: process.env.GITHUB_CALLBACK_URL || 'http://localhost:3000/auth/github/callback'
}, (accessToken, refreshToken, profile, done) => {
  return done(null, { provider: 'github', profile, accessToken });
}));

// Auth routes
app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));
app.get('/auth/google/callback', passport.authenticate('google', { failureRedirect: '/login-failure' }), (req, res) => {
  res.redirect('/profile');
});

app.get('/auth/github', passport.authenticate('github', { scope: ['user:email'] }));
app.get('/auth/github/callback', passport.authenticate('github', { failureRedirect: '/login-failure' }), (req, res) => {
  res.redirect('/profile');
});

app.get('/login-failure', (req, res) => {
  res.send('<h2>Falha no login</h2><p><a href="/">Voltar</a></p>');
});

function ensureAuth(req, res, next) {
  if (req.isAuthenticated && req.isAuthenticated()) return next();
  res.redirect('/');
}

app.get('/profile', ensureAuth, (req, res) => {
  const user = req.user || {};
  const profile = user.profile || {};
  const displayName = profile.displayName || (profile.username || 'Usuário');
  const photo = (profile.photos && profile.photos[0] && profile.photos[0].value) || '';
  res.send(`<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Perfil</title><link rel="stylesheet" href="css/style.css"></head><body><main style="display:flex;align-items:center;justify-content:center;height:100vh;color:#fff;background:#081222"><div style="background:rgba(255,255,255,0.03);padding:28px;border-radius:12px;text-align:center"><h2>${displayName}</h2>${photo?`<img src="${photo}" alt="avatar" style="width:120px;height:120px;border-radius:50%;object-fit:cover;margin:12px 0">`:''}<p>Logado com: ${user.provider}</p><p><a href="/logout">Sair</a></p></div></main></body></html>`);
});

app.get('/logout', (req, res) => {
  req.logout(() => {});
  req.session.destroy(() => res.redirect('/'));
});

app.listen(PORT, () => console.log(`OAuth server rodando em http://localhost:${PORT}`));
