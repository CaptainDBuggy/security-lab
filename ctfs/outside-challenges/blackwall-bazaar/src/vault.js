const path = require('path');

// Obscured, unguessable path. Only revealed in the download link you get AFTER a
// purchase — so you can't just fuzz your way to /vault/.
const VAULT_URL = '/vault-7f3a9c2b';
const VAULT_DIR = path.join(__dirname, '..', 'vault');

function slug(name) {
  return String(name).toLowerCase().replace(/[^a-z0-9]+/g, '_').replace(/^_+|_+$/g, '');
}
function fileFor(name) {
  return slug(name) + '.bin';
}

module.exports = { VAULT_URL, VAULT_DIR, slug, fileFor };
