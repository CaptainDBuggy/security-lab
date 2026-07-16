// ---------------------------------------------------------------------------
// ICE FLARE — server-side breach detection.
//
// When the player successfully pulls off an exploit, the server notices and
// queues a "flare". The client drains the queue (GET /api/flare) and throws a
// full-screen glitch. In-world: the market's ICE twitching because you just did
// something you weren't meant to. Fires on SUCCESS only, so it doubles as a
// "yeah, that landed" tell.
// ---------------------------------------------------------------------------

const STAGES = {
  INVITE:   { code: 'INVITE',   msg: 'FORGED INVITE ACCEPTED' },
  NOSQLI:   { code: 'NOSQLI',   msg: 'QUERY OPERATOR INJECTION' },
  TRANSFER: { code: 'TRANSFER', msg: 'NEGATIVE WIRE // EDDIES SIPHONED' },
  VAULT:    { code: 'VAULT',    msg: 'VAULT INDEX EXPOSED' },
  SYSOP:    { code: 'SYSOP',    msg: 'OPERATOR CONSOLE BREACHED' },
  RCE:      { code: 'RCE',      msg: 'REMOTE COMMAND EXECUTED' },
};

function triggerBreach(req, stageKey, extra) {
  if (!req || !req.session) return;
  const s = STAGES[stageKey];
  if (!s) return;
  if (!req.session.flares) req.session.flares = [];
  req.session.flares.push({ stage: s.code, msg: extra || s.msg, t: Date.now() });
  // keep the queue from growing without bound if the client never drains it
  if (req.session.flares.length > 20) req.session.flares.shift();
}

function drainFlares(req) {
  if (!req || !req.session || !req.session.flares) return [];
  const out = req.session.flares;
  req.session.flares = [];
  return out;
}

module.exports = { STAGES, triggerBreach, drainFlares };
