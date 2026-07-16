const path = require('path');
const express = require('express');
const session = require('express-session');
const serveIndex = require('serve-index');

const { connect, db } = require('./src/db');
const { drainFlares, triggerBreach } = require('./src/breach');
const { seedIfEmpty } = require('./seed');
const { ensureVault } = require('./build/populate_vault');
const { VAULT_URL, VAULT_DIR } = require('./src/vault');

const app = express();
const PORT = process.env.PORT || 3000;

// Views
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Body + query parsing. NOTE: express default 'extended' query parser (qs) turns
// ?q[$ne]= into { q: { $ne: '' } } — that's the NoSQL injection surface, left on
// on purpose.
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Static public assets. public/index.html is also the ZipCrypto known-plaintext
// crib baked into the backup zip.
// index:false so "/" falls through to the dynamic splash route; /index.html
// (the ZipCrypto crib) is still served explicitly.
app.use(express.static(path.join(__dirname, 'public'), { index: false }));

app.use(session({
  secret: 'chr0me-and-c1rcuits',
  resave: false,
  saveUninitialized: true,
  cookie: { httpOnly: true },
}));

// Make the logged-in runner (and their fresh doc, for the eddies counter in the
// nav) available to every view.
app.use(async (req, res, next) => {
  res.locals.runner = req.session.runner || null;
  req.me = null;
  if (req.session.runner) {
    try { req.me = await db().collection('users').findOne({ handle: req.session.runner.handle }); }
    catch (e) { /* ignore */ }
  }
  res.locals.me = req.me;
  next();
});

// ICE FLARE drain — the client polls this and fires the glitch for each flare.
app.get('/api/flare', (req, res) => {
  res.json({ flares: drainFlares(req) });
});

// Routes
app.use('/', require('./src/routes/auth'));
app.use('/', require('./src/routes/market'));
app.use('/', require('./src/routes/wallet'));
app.use('/', require('./src/routes/sysop'));

// The vault download dir — indexing left ON. Hitting the bare directory index
// (as opposed to a specific file) is the "forced browsing" breach.
app.use(VAULT_URL, (req, res, next) => {
  if (req.path === '/' || req.path === '') triggerBreach(req, 'VAULT', 'VAULT INDEX EXPOSED');
  next();
});
app.use(VAULT_URL, express.static(VAULT_DIR));
app.use(VAULT_URL, serveIndex(VAULT_DIR, { icons: true, view: 'details' }));

// health
app.get('/healthz', (req, res) => res.type('text').send('ok'));

// Themed catch-all error handler — a thrown handler returns a clean 500, not a stack.
app.use((err, req, res, next) => {
  console.error('[bazaar] error:', err && err.message);
  if (res.headersSent) return next(err);
  res.status(500).type('text').send('// system fault // the ICE hiccuped');
});

// Belt-and-suspenders: a malformed injection payload that rejects deep in a
// driver call must never be able to flatline the whole box.
process.on('unhandledRejection', (e) => console.error('[bazaar] unhandledRejection:', e && e.message));

connect()
  .then(async () => {
    const seeded = await seedIfEmpty(db());
    if (seeded) console.log('[bazaar] seeded fresh roster + wares');
    ensureVault();
    app.listen(PORT, () => console.log(`[bazaar] jacked in on :${PORT}`));
  })
  .catch((err) => {
    console.error('[bazaar] mongo connection failed:', err.message);
    process.exit(1);
  });
