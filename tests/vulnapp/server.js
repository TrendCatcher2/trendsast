const express = require('express');
const { exec } = require('child_process');
const fs = require('fs');
const axios = require('axios');
const _ = require('lodash');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const app = express();
const User = require('./models/user');

app.get('/user', (req, res) => {
  db.query("SELECT * FROM users WHERE id = " + req.query.id, (e, r) => res.json(r));
});
app.get('/ping', (req, res) => { exec('ping -c1 ' + req.query.host); res.send('ok'); });
app.get('/file', (req, res) => { fs.readFile('/var/data/' + req.query.name, (e, d) => res.send(d)); });
app.get('/fetch', async (req, res) => { const r = await axios.get(req.query.url); res.json(r.data); });
app.get('/go', (req, res) => res.redirect(req.query.next));
app.get('/hi', (req, res) => res.send('<h1>Hello ' + req.query.name + '</h1>'));
app.post('/login', async (req, res) => { const u = await User.findOne({ user: req.body.user, pass: req.body.pass }); res.json(u); });
app.post('/settings', (req, res) => { const s = {}; _.merge(s, req.body); res.json(s); });
app.post('/register', async (req, res) => { const u = new User(req.body); await u.save(); res.json(u); });
app.get('/calc', (req, res) => res.send(String(eval(req.query.expr))));
app.get('/search', (req, res) => { const re = new RegExp(req.query.q); res.json([]); });
const token = jwt.sign({ id: 1 }, "hardcoded-secret-123");
function resetToken() { return Math.random().toString(36).slice(2); }
const h = crypto.createHash("md5");
window.addEventListener("message", function (e) { document.getElementById("x").innerHTML = e.data; });
document.getElementById("y").innerHTML = location.hash.slice(1);
const cfg = { apiKey: "AKIA1234567890ABCDEF" };
