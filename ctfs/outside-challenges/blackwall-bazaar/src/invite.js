// ---------------------------------------------------------------------------
// Invite codes.
//
// A code is just base64("jpx" + <counter>).  "jpx1204" -> "anB4MTIwNA=="
// They LOOK random. They are not. They're a sequential counter behind a coat
// of base64 paint.
//
// THE BUG: validation is range-based, not membership-based. Any counter that
// falls inside the active batch window [VALID_MIN, VALID_MAX] and hasn't been
// claimed yet is accepted — whether or not it was ever actually issued to a
// real invitee. So you can mint your own.
//
// The sample shown on the door is an OLD code (SAMPLE_COUNTER) that's already
// below the active window, so it's dead. Decode it, learn the shape, then grind
// the counter forward until one lands inside the live window.
// ---------------------------------------------------------------------------

const PREFIX = 'jpx';

const VALID_MIN = 1150;   // active batch window — lower bound
const VALID_MAX = 1400;   // active batch window — upper bound
const SAMPLE_COUNTER = 1000; // the dead example printed on the splash

// Codes that were ACTUALLY issued to real invitees (sparse). Validation never
// checks this set — it's only used to detect a forged (never-issued) code so
// the ICE FLARE can fire.
const ISSUED = new Set([1163, 1189, 1204, 1237, 1266, 1298, 1301, 1355, 1377, 1400]);

function encode(counter) {
  return Buffer.from(PREFIX + counter).toString('base64');
}

function decode(code) {
  try {
    const s = Buffer.from(String(code), 'base64').toString('utf8');
    if (!s.startsWith(PREFIX)) return null;
    const n = parseInt(s.slice(PREFIX.length), 10);
    return Number.isInteger(n) && String(n) === s.slice(PREFIX.length) ? n : null;
  } catch (e) {
    return null;
  }
}

function sampleCode() {
  return encode(SAMPLE_COUNTER);
}

// The vulnerable check: in-window + not-yet-claimed. Never checks ISSUED.
function isValidCounter(counter, claimedSet) {
  if (counter === null || counter === undefined) return false;
  if (counter < VALID_MIN || counter > VALID_MAX) return false;
  if (claimedSet && claimedSet.has(counter)) return false;
  return true;
}

function wasIssued(counter) {
  return ISSUED.has(counter);
}

module.exports = {
  PREFIX, VALID_MIN, VALID_MAX, SAMPLE_COUNTER,
  encode, decode, sampleCode, isValidCounter, wasIssued,
};
