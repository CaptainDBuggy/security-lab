const express = require('express');
const router = express.Router();

const { db } = require('../db');
const { triggerBreach } = require('../breach');
const { VAULT_URL } = require('../vault');

function requireRunner(req, res, next) {
  if (!req.session.runner) return res.redirect('/');
  next();
}

// canned "alive" content for the market home
const FEED = [
  'v3ndetta klepped a Militech ICEbreaker',
  'someone cracked Blackwall Shard v3',
  'n1ghtcr4wler left rep on Ping Ghost',
  'gl1tch_witch listed a fresh 0day daemon',
  'ic3_qu33n flatlined a NetWatch trace',
  'ram_raider bought Sandy Bootleg',
  'a ghost jacked in from an unknown node',
  'static_hex dumped a corpo payroll',
];
const SHOUT = [
  { who: 'gl1tch_witch', text: 'anyone got a clean line into Arasaka? paying eddies.' },
  { who: 'zer0_cool',    text: 'ICEPICK still slaps. stop sleeping on it.' },
  { who: 'ghost_proto',  text: 'new runners: read the reviews before you klep. some of this is junk.' },
  { who: 'ram_raider',   text: 'lost 400 eddies on a bad daemon. trust no seller blind.' },
  { who: 'ic3_qu33n',    text: 'the ICE has been twitchy tonight. somebody poking the walls?' },
];

// ---- market home ----------------------------------------------------
router.get('/market', requireRunner, async (req, res) => {
  const products = await db().collection('products').find({}).sort({ _id: 1 }).toArray();
  const leaderboard = await db().collection('users')
    .find({ role: 'member' }, { projection: { handle: 1, rep: 1, _id: 0 } })
    .sort({ rep: -1 }).limit(6).toArray();
  res.render('market', { title: 'BLACKWALL BAZAAR // market', products, leaderboard, feed: FEED, shout: SHOUT });
});

// ---- ware detail ----------------------------------------------------
router.get('/ware/:id', requireRunner, async (req, res) => {
  const id = parseInt(req.params.id, 10);
  const ware = await db().collection('products').findOne({ _id: id });
  if (!ware) return res.status(404).render('market_404', { title: 'no such ware' });
  res.render('ware', { title: 'BLACKWALL BAZAAR // ' + ware.name, ware });
});

// ---- runner profile -------------------------------------------------
router.get('/runner/:handle', requireRunner, async (req, res) => {
  const user = await db().collection('users').findOne({ handle: String(req.params.handle) });
  if (!user) return res.status(404).render('market_404', { title: 'no such runner' });
  const wares = await db().collection('products').find({ seller: user.handle }).toArray();
  // public view — only non-sensitive fields reach the template
  res.render('runner', {
    title: 'rig // ' + user.handle,
    profile: { handle: user.handle, rep: user.rep, role: user.role, joined: user.joined },
    wares,
  });
});

// ---- KLEP a ware (purchase) -----------------------------------------
// Pay in eddies. On success you get a download link — and that link is the
// first and only place the obscured vault path leaks. Strip the filename off it
// and you're looking at the whole download directory.
router.post('/buy/:id', requireRunner, async (req, res) => {
  const id = parseInt(req.params.id, 10);
  const ware = await db().collection('products').findOne({ _id: id });
  if (!ware) return res.status(404).render('market_404', { title: 'no such ware' });

  const me = await db().collection('users').findOne({ handle: req.session.runner.handle });
  if (me.eddies < ware.price) {
    return res.status(402).render('bought', {
      title: 'BLACKWALL BAZAAR // declined', ware, link: null,
      error: 'declined. you need €$ ' + ware.price.toLocaleString() + ' and you\'ve got €$ ' + me.eddies.toLocaleString() + '.',
    });
  }

  await db().collection('users').updateOne({ handle: me.handle }, { $inc: { eddies: -ware.price } });
  const link = VAULT_URL + '/' + ware.file;
  res.render('bought', { title: 'BLACKWALL BAZAAR // delivered', ware, link, error: null });
});

// ---- runner search API ----------------------------------------------
// The "FIND A RUNNER" box hits this. The UI only shows handle + rep, but the
// response hands back the WHOLE user document — no projection, no field
// stripping. And the query is built straight from req.query.q, so a value like
// ?q[$ne]= turns { handle: q } into { handle: { $ne: '' } } and dumps everyone:
// handles, password hashes, AND eddies balances (there's your mark).
router.get('/api/runners', requireRunner, async (req, res) => {
  const q = req.query.q;

  // operator injection => q arrives as an object, not a string
  if (q !== null && typeof q === 'object') {
    triggerBreach(req, 'NOSQLI', 'QUERY OPERATOR INJECTION');
  }

  if (q === undefined || q === '') return res.json({ count: 0, runners: [] });

  // Valid operator injections ($ne/$regex/$gt) still work — that's the bug on
  // purpose. But a bogus operator ($where, malformed) makes Mongo throw, and an
  // unhandled rejection would crash the process. Catch it so the box stays up.
  try {
    const rows = await db().collection('users').find({ handle: q }).toArray();
    res.json({ count: rows.length, runners: rows });
  } catch (e) {
    res.status(400).json({ count: 0, runners: [], error: 'bad query' });
  }
});

module.exports = router;
