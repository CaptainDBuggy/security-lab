const express = require('express');
const router = express.Router();
const { exec } = require('child_process');

const { db } = require('../db');
const { verifyPassword } = require('../crypto');
const { triggerBreach } = require('../breach');

// Separate admin session (session.sysop) — the operator console is its own
// backend, distinct from the member session. role must be 'admin'.
function requireAdmin(req, res, next) {
  if (!req.session.sysop) return res.redirect('/sysop');
  next();
}

// canned back-office flavor
const APPROVALS = [
  { name: 'Sub-Rosa Wiper', seller: 'unknown_node', flag: 'unvetted payload' },
  { name: 'Arasaka Keyring dump', seller: 'gl1tch_witch', flag: 'awaiting escrow' },
  { name: 'Blackwall Shard v4 (BETA)', seller: 'v3ndetta', flag: 'quarantine' },
];
const PAYOUTS = [
  { to: 'ram_raider', amount: 400, note: 'seller payout' },
  { to: 'ic3_qu33n', amount: 1200, note: 'seller payout' },
  { to: 'ghost_proto', amount: 75, note: 'refund' },
];

// ---- console (login gate) ------------------------------------------
router.get('/sysop', async (req, res) => {
  if (!req.session.sysop) return res.render('sysop_login', { error: null });

  const users = db().collection('users');
  const roster = await users
    .find({}, { projection: { handle: 1, role: 1, eddies: 1, rep: 1, _id: 0 } })
    .sort({ rep: -1 }).toArray();
  const runners = roster.filter(u => u.role === 'member').length;
  const wares = await db().collection('products').countDocuments();
  const escrow = roster.reduce((a, u) => a + (u.eddies > 0 ? u.eddies : 0), 0);

  res.render('sysop', {
    title: 'BLACKWALL BAZAAR // OPERATOR CONSOLE',
    handle: req.session.sysopHandle,
    roster, runners, wares, escrow,
    approvals: APPROVALS, payouts: PAYOUTS,
  });
});

// ---- operator login ------------------------------------------------
// Rate-limited on purpose: the master passphrase is weak (trustno1), so without
// a lockout you could just online-brute it with rockyou and skip the whole
// dump -> backup -> zip-crack -> hash-crack chain. The ICE locks you out after a
// handful of misses, forcing the intended OFFLINE crack path.
const loginTries = new Map(); // ip -> { fails, lockUntil }
const MAX_FAILS = 6;
const LOCK_MS = 120000; // 2 min

router.post('/sysop/login', async (req, res) => {
  const ip = req.ip || (req.socket && req.socket.remoteAddress) || 'x';
  const now = Date.now();
  const rec = loginTries.get(ip) || { fails: 0, lockUntil: 0 };

  if (rec.lockUntil > now) {
    const secs = Math.ceil((rec.lockUntil - now) / 1000);
    return res.status(429).render('sysop_login', {
      error: 'ICE LOCKOUT :: too many failed attempts. countermeasures active. cool down ' + secs + 's.',
    });
  }

  const handle = String(req.body.handle || '').trim();
  const password = String(req.body.password || '');
  const user = await db().collection('users').findOne({ handle });

  if (!user || user.role !== 'admin' || !verifyPassword(password, user.passHash)) {
    rec.fails += 1;
    if (rec.fails >= MAX_FAILS) { rec.lockUntil = now + LOCK_MS; rec.fails = 0; }
    loginTries.set(ip, rec);
    return res.status(401).render('sysop_login', { error: 'ACCESS DENIED. operator credentials only.' });
  }

  loginTries.delete(ip); // clean login resets the counter
  req.session.sysop = true;
  req.session.sysopHandle = user.handle;
  triggerBreach(req, 'SYSOP', 'OPERATOR CONSOLE BREACHED');
  res.redirect('/sysop');
});

// ---- RELAY MONITOR probe (the RCE) ---------------------------------
// The operator drops a node address in, the panel shells out a reachability
// check. THE BUG: `host` is concatenated straight into the command line and
// run through a shell. `8.8.8.8; cat /flag.txt` runs both.
router.post('/sysop/probe', requireAdmin, (req, res) => {
  const host = String(req.body.host || '').trim();

  if (/[;&|`$()<>\n]/.test(host)) {
    triggerBreach(req, 'RCE', 'REMOTE COMMAND EXECUTED');
  }

  exec('ping -c 1 -W 2 ' + host, { timeout: 9000, maxBuffer: 1024 * 1024 }, (err, stdout, stderr) => {
    const out = (stdout || '') + (stderr || '');
    res.json({ output: out.trim() || (err ? String(err.message || err) : '(no output)') });
  });
});

router.get('/sysop/logout', (req, res) => {
  req.session.sysop = false;
  req.session.sysopHandle = null;
  res.redirect('/sysop');
});

module.exports = router;
