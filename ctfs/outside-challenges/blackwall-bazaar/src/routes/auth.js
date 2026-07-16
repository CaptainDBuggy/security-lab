const express = require('express');
const router = express.Router();

const { db } = require('../db');
const invite = require('../invite');
const { hashPassword, verifyPassword } = require('../crypto');
const { triggerBreach } = require('../breach');

// Set of invite counters already claimed by a registered runner.
async function claimedCounters() {
  const rows = await db().collection('users')
    .find({ inviteCounter: { $exists: true } }, { projection: { inviteCounter: 1 } })
    .toArray();
  return new Set(rows.map(r => r.inviteCounter));
}

// Validate a code the vulnerable way (range-based, ignores whether it was issued).
// Returns { ok, reason }.
async function validateCode(code) {
  const counter = invite.decode(code);
  if (counter === null) return { ok: false, reason: 'that code is malformed. it decodes to garbage.' };
  const claimed = await claimedCounters();
  if (counter < invite.VALID_MIN || counter > invite.VALID_MAX)
    return { ok: false, reason: 'that code is expired. the batch it belongs to is dead.' };
  if (claimed.has(counter)) return { ok: false, reason: 'that code is already claimed.' };
  return { ok: true, counter };
}

// ---- the door -------------------------------------------------------
router.get('/', (req, res) => {
  if (req.session.runner) return res.redirect('/market');
  res.render('splash', { sampleCode: invite.sampleCode() });
});

// ---- the oracle -----------------------------------------------------
// Check a code without committing. This is what you script the brute against.
router.get('/check-invite', async (req, res) => {
  const code = req.query.code || '';
  const counter = invite.decode(code);
  if (counter === null) return res.json({ valid: false, reason: 'malformed' });
  const claimed = await claimedCounters();
  if (counter < invite.VALID_MIN || counter > invite.VALID_MAX)
    return res.json({ valid: false, reason: 'expired', counter });
  if (claimed.has(counter)) return res.json({ valid: false, reason: 'claimed', counter });
  return res.json({ valid: true, counter });
});

// ---- STEP 1: the gate ----------------------------------------------
// Just the code. A valid one opens the registration form (with the code carried
// through in a hidden field). No account yet, and NO breach here — the flare is
// saved for the browser step so the player actually sees it.
router.post('/gate', async (req, res) => {
  const code = String(req.body.invite || '').trim();
  if (!code) return res.status(400).render('splash', { sampleCode: invite.sampleCode(), error: 'paste a code, choom.' });

  const v = await validateCode(code);
  if (!v.ok) return res.status(400).render('splash', { sampleCode: invite.sampleCode(), error: v.reason });

  // gate opens — hand them the registration form carrying the accepted code
  res.render('register', { invite: code });
});

// ---- STEP 2: register (carry the code through) ---------------------
// The code is re-validated here so you can't skip the gate by POSTing straight
// in. THIS is where the forged-invite breach fires — on a real browser submit.
router.post('/register', async (req, res) => {
  const code = String(req.body.invite || '').trim();
  const handle = String(req.body.handle || '').trim();
  const password = String(req.body.password || '');

  const v = await validateCode(code);
  if (!v.ok) return res.status(400).render('splash', { sampleCode: invite.sampleCode(), error: v.reason });

  if (!handle || !password)
    return res.status(400).render('register', { invite: code, error: 'handle and passphrase required.' });

  const users = db().collection('users');
  if (await users.findOne({ handle }))
    return res.status(400).render('register', { invite: code, error: 'handle already taken. pick another.' });

  const doc = {
    handle,
    passHash: hashPassword(password),
    role: 'member',
    eddies: 0,
    rep: 0,
    inviteCounter: v.counter,
    joined: new Date(),
  };
  await users.insertOne(doc);

  // Forged? (valid-range code that was never actually issued.) Flare on the
  // browser submit so the glitch is seen.
  if (!invite.wasIssued(v.counter)) triggerBreach(req, 'INVITE', 'FORGED INVITE ACCEPTED');

  req.session.runner = { handle: doc.handle, role: doc.role };
  res.redirect('/market');
});

// ---- login (returning runner) --------------------------------------
router.post('/login', async (req, res) => {
  // coerced to strings on purpose — login is NOT an injection point.
  const handle = String(req.body.handle || '').trim();
  const password = String(req.body.password || '');

  const user = await db().collection('users').findOne({ handle });
  if (!user || !user.passHash || !verifyPassword(password, user.passHash)) {
    return res.status(401).render('splash', { sampleCode: invite.sampleCode(), error: 'bad handle or passphrase.' });
  }
  req.session.runner = { handle: user.handle, role: user.role };
  res.redirect('/market');
});

router.get('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/'));
});

module.exports = router;
