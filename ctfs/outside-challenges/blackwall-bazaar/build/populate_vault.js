// Fills the vault download dir with a file per ware (so purchase links resolve)
// and, in local dev, a placeholder backup. In Docker, build/make_backup.sh
// overwrites the placeholder with the REAL ZipCrypto backup.
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { VAULT_DIR, fileFor } = require('../src/vault');
const { PRODUCTS } = require('../seed');

function ensureVault() {
  fs.mkdirSync(VAULT_DIR, { recursive: true });
  for (const p of PRODUCTS) {
    const f = path.join(VAULT_DIR, fileFor(p.name));
    if (!fs.existsSync(f)) fs.writeFileSync(f, crypto.randomBytes(1200 + Math.floor(Math.random() * 3000)));
  }
  const bak = path.join(VAULT_DIR, 'nc_market_backup_0417.zip');
  if (!fs.existsSync(bak)) {
    fs.writeFileSync(bak, '# placeholder — the real ZipCrypto backup is built in the Docker image via build/make_backup.sh\n');
  }
  return true;
}

module.exports = { ensureVault };

if (require.main === module) { ensureVault(); console.log('[vault] populated'); }
