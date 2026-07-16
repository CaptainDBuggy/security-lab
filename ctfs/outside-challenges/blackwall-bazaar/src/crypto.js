const crypto = require('crypto');

// ---------------------------------------------------------------------------
// Password hashing for the Bazaar.
//
// hash = sha256( SALT + password )   -> hashcat mode 1420 : sha256($salt.$pass)
//
// SALT is a global secret pepper. It NEVER touches the database, so dumping the
// users collection gets you the hashes but not the salt. The only place it lives
// is right here in the source. Get the source (the backup zip), get the salt,
// and the offline crack finally has everything it needs.
// ---------------------------------------------------------------------------
const SALT = 'bl4ckw4ll_p3pp3r_2077';

function hashPassword(pw) {
  return crypto.createHash('sha256').update(SALT + String(pw)).digest('hex');
}

function verifyPassword(pw, hash) {
  return hashPassword(pw) === hash;
}

module.exports = { SALT, hashPassword, verifyPassword };
