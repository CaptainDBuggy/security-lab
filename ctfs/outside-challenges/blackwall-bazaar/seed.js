// ---------------------------------------------------------------------------
// Seeds the Bazaar: the runner roster, the admin, the ware catalog, reviews.
// Idempotent — seedIfEmpty() only runs when the box is fresh (no 0P3R4T0R yet).
// ---------------------------------------------------------------------------
const crypto = require('crypto');
const { hashPassword } = require('./src/crypto');
const { fileFor } = require('./src/vault');

function strongRandom() {
  // NPC passphrases: 32 random bytes. Same salt as everyone, but uncrackable.
  return crypto.randomBytes(32).toString('hex');
}

// Members — handles, rep, and eddies. v3ndetta is the loaded one (the mark).
const RUNNERS = [
  { handle: 'v3ndetta',     rep: 9001, eddies: 52400 },
  { handle: 'gl1tch_witch', rep: 4200, eddies: 8100 },
  { handle: 'zer0_cool',    rep: 3110, eddies: 3400 },
  { handle: 'n1ghtcr4wler', rep: 2755, eddies: 1950 },
  { handle: 'ram_raider',   rep: 1600, eddies: 900 },
  { handle: 'ic3_qu33n',    rep: 1400, eddies: 640 },
  { handle: 'ghost_proto',  rep: 980,  eddies: 275 },
  { handle: 'dr_chr0me',    rep: 610,  eddies: 120 },
  { handle: 'static_hex',   rep: 300,  eddies: 45 },
];

// The market operator. Weak password ON PURPOSE — this is the hash you crack.
const ADMIN = { handle: '0P3R4T0R', rep: 0, eddies: 0, password: 'trustno1' };

const PRODUCTS = [
  { _id: 1,  name: 'ICEPICK',            seller: 'v3ndetta',     price: 3200,
    blurb: 'Militech-grade ICE breaker daemon. Melts corpo walls like they were never there.',
    reviews: [
      { who: 'gl1tch_witch', stars: 5, text: 'punched through Arasaka ICE first try. v3ndetta doesnt miss. eddies well spent.' },
      { who: 'static_hex',   stars: 4, text: 'overpriced. works tho.' },
    ] },
  { _id: 2,  name: 'Blackwall Shard v3', seller: 'v3ndetta',     price: 12000,
    blurb: 'A fragment off the wall itself. Handle it or it handles you. Not for gonks.',
    reviews: [
      { who: 'n1ghtcr4wler', stars: 3, text: 'youre a gonk if you run this without a subnet buffer. lost a runner to it.' },
    ] },
  { _id: 3,  name: 'Ping Ghost',         seller: 'gl1tch_witch', price: 800,
    blurb: 'Traceless recon. They never see you knock. Cleanest scanner on the wire.',
    reviews: [
      { who: 'zer0_cool', stars: 5, text: 'never tripped a single trace. preem.' },
    ] },
  { _id: 4,  name: 'Short Circuit',      seller: 'zer0_cool',    price: 1500,
    blurb: "Fry a target's chrome from across the room. Smells like burnt cyberware.",
    reviews: [] },
  { _id: 5,  name: 'Contagion',          seller: 'n1ghtcr4wler', price: 2100,
    blurb: 'Self-spreading daemon. Set it loose, walk away, watch the subnet fall.',
    reviews: [
      { who: 'ram_raider', stars: 4, text: 'spread faster than i wanted lol. keep a killswitch handy.' },
    ] },
  { _id: 6,  name: 'Reboot Optics',      seller: 'ic3_qu33n',    price: 650,
    blurb: 'Blind a whole camera grid for 30 seconds. Just enough time to vanish.',
    reviews: [] },
  { _id: 7,  name: 'Sandy Bootleg',      seller: 'ram_raider',   price: 4400,
    blurb: 'Cut-rate Sandevistan firmware. Time slows. Mostly. No refunds on ghost-frames.',
    reviews: [
      { who: 'dr_chr0me', stars: 2, text: 'gave me a stutter in the corner of my eye for a week. runs tho.' },
    ] },
  { _id: 8,  name: 'NetWatch Bypass',    seller: 'v3ndetta',     price: 9800,
    blurb: "The ICE the badges don't want in your hands. If they knew you had this you'd be flatlined.",
    reviews: [
      { who: 'gl1tch_witch', stars: 5, text: 'walked past a NetWatch node like it was asleep. worth every eddie.' },
    ] },
  { _id: 9,  name: 'Voodoo Starter Kit', seller: 'ghost_proto',  price: 300,
    blurb: 'Everything a fresh runner needs to not flatline on day one. Cheapest door in.',
    reviews: [
      { who: 'static_hex', stars: 4, text: 'solid starter. the bundled scanner alone is worth it.' },
    ] },
  { _id: 10, name: '0xDEADBEEF',         seller: 'static_hex',   price: 500,
    blurb: 'Mystery data dump. Could be a corpo payroll. Could be a trap. Roll the dice.',
    reviews: [
      { who: 'gl1tch_witch', stars: 5, text: 'opened mine and got a corpos payroll dump lmao. worth the gamble.' },
    ] },
];

async function seedIfEmpty(db) {
  const users = db.collection('users');
  if (await users.findOne({ handle: ADMIN.handle })) return false;

  const now = new Date();
  const memberDocs = RUNNERS.map((r, i) => ({
    handle: r.handle,
    passHash: hashPassword(strongRandom()),
    role: 'member',
    eddies: r.eddies,
    rep: r.rep,
    joined: new Date(now.getTime() - (i + 3) * 86400000),
  }));
  const adminDoc = {
    handle: ADMIN.handle,
    passHash: hashPassword(ADMIN.password),
    role: 'admin',
    eddies: ADMIN.eddies,
    rep: ADMIN.rep,
    joined: new Date(now.getTime() - 400 * 86400000),
  };
  await users.insertMany([...memberDocs, adminDoc]);

  const products = db.collection('products');
  await products.deleteMany({});
  // stamp the deliverable filename each ware maps to in the vault
  PRODUCTS.forEach(p => { p.file = fileFor(p.name); });
  await products.insertMany(PRODUCTS);

  return true;
}

module.exports = { seedIfEmpty, PRODUCTS };

// Standalone: `node seed.js` — forces a reseed.
if (require.main === module) {
  const { connect, db } = require('./src/db');
  connect().then(async () => {
    await db().collection('users').deleteMany({});
    await db().collection('products').deleteMany({});
    await seedIfEmpty(db());
    const n = await db().collection('users').countDocuments();
    console.log(`[seed] done — ${n} users, ${await db().collection('products').countDocuments()} wares`);
    process.exit(0);
  }).catch(e => { console.error(e); process.exit(1); });
}
