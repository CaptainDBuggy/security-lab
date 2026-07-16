const express = require('express');
const router = express.Router();

const { db } = require('../db');
const { triggerBreach } = require('../breach');

function requireRunner(req, res, next) {
  if (!req.session.runner) return res.redirect('/');
  next();
}

// ---- your rig / wallet ---------------------------------------------
router.get('/rig', requireRunner, async (req, res) => {
  res.render('rig', {
    title: 'BLACKWALL BAZAAR // your rig',
    flash: req.query.flash || null,
    detail: req.query.detail || null,
    ok: req.query.ok === '1',
  });
});

// ---- WIRE EDDIES (the transfer) ------------------------------------
// Move eddies from you to another runner.
//
// THE BUG: the amount's sign is never checked. The dev even added a "balance"
// guard — if (me.eddies < amount) reject — and felt safe. But a NEGATIVE amount
// walks straight through it (0 < -50000 is false), and then the arithmetic
// runs in reverse:
//     me.eddies      -= amount   // -= (-50000)  => you GAIN
//     target.eddies  += amount   // += (-50000)  => they LOSE
// A negative "send" is a theft. Pick the richest runner and drain them.
router.post('/transfer', requireRunner, async (req, res) => {
  const users = db().collection('users');
  const me = await users.findOne({ handle: req.session.runner.handle });

  const to = String(req.body.to || '').trim();
  const amount = Number(req.body.amount);

  const back = (flash, ok) => res.redirect('/rig?flash=' + encodeURIComponent(flash) + (ok ? '&ok=1' : ''));

  if (!to) return back('name a runner to wire to.');
  if (!Number.isFinite(amount)) return back('that amount is garbage.');
  if (to === me.handle) return back("you can't wire yourself, choom.");

  const target = await users.findOne({ handle: to });
  if (!target) return back('no runner by that handle.');

  // the "guard" the dev thought made this safe
  if (me.eddies < amount) return back('insufficient eddies.');

  await users.updateOne({ handle: me.handle }, { $inc: { eddies: -amount } });
  await users.updateOne({ handle: target.handle }, { $inc: { eddies: amount } });

  if (amount < 0) {
    triggerBreach(req, 'TRANSFER', 'NEGATIVE WIRE // EDDIES SIPHONED');
    return res.redirect('/rig?flash=' + encodeURIComponent('wired €$ ' + amount + ' to @' + to + '...') + '&ok=1');
  }

  return res.redirect('/rig?flash=' + encodeURIComponent('sent €$ ' + amount + ' to @' + to) + '&ok=1');
});

module.exports = router;
