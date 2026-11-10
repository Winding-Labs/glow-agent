// Glow's listing mail relay: an Apps Script web app on the account of a member of the listings Google Group
// (listing@<your domain>). The glow-sites helper on your Mac asks it for the verification mail a listing run is waiting
// for (lib/sites.mjs relayMail). It answers only a caller with the key whose SHA-256 is below (the key itself stays in
// that Mac's keychain), and only for mail to listing+<product>@<this account's domain> from the last 30 minutes, at most
// 10 messages, as text: nothing else in the mailbox. Read-only: the Gmail advanced service with gmail.readonly.
//
// Set up: `npx @winding-labs/glow sites connect-mail` in a terminal on the Mac walks through it. script.google.com › New
// project › this as Code.gs › Project settings › Show "appsscript.json" › the manifest below › the KEY_SHA256 line
// connect-mail prints › Deploy › New deployment › Web app, execute as Me, access Anyone › Authorize › paste its URL.
//
// appsscript.json:
// {"timeZone": "America/Los_Angeles", "runtimeVersion": "V8", "exceptionLogging": "STACKDRIVER",
//  "oauthScopes": ["https://www.googleapis.com/auth/gmail.readonly"],
//  "dependencies": {"enabledAdvancedServices": [{"userSymbol": "Gmail", "version": "v1", "serviceId": "gmail"}]},
//  "webapp": {"executeAs": "USER_DEPLOYING", "access": "ANYONE_ANONYMOUS"}}

var KEY_SHA256 = '';
var WINDOW_MS = 30 * 60 * 1000;

function doPost(e) {
  var body = {};
  try {
    body = JSON.parse(e.postData.contents) || {};
  } catch (err) {
    body = {};
  }
  if (!/^[0-9a-f]{64}$/.test(KEY_SHA256) || sha256(String(body.key || '')) !== KEY_SHA256) return reply({ ok: false, error: 'unauthorized' });
  var alias = String(body.alias || '').toLowerCase();
  var domain = String(Gmail.Users.getProfile('me').emailAddress).split('@')[1].toLowerCase();
  if (!/^listing\+[a-z0-9-]{1,40}@/.test(alias) || alias.split('@')[1] !== domain) return reply({ ok: false, error: 'not_a_listing_alias' });
  var since = Date.now() - WINDOW_MS;
  var found = Gmail.Users.Messages.list('me', { q: 'to:' + alias + ' after:' + Math.floor(since / 1000), maxResults: 10, includeSpamTrash: true });
  var messages = [];
  (found.messages || []).forEach(function (m) {
    var msg = Gmail.Users.Messages.get('me', m.id, { format: 'full' });
    var to = (msg.payload.headers || []).filter(function (h) { return /^(to|cc|delivered-to)$/i.test(h.name); })
      .map(function (h) { return String(h.value).toLowerCase(); }).join(' ');
    if (Number(msg.internalDate) < since || to.indexOf(alias) < 0) return;
    messages.push({ at: Number(msg.internalDate), text: texts(msg.payload, []).join('\n').slice(0, 200000) });
  });
  return reply({ ok: true, messages: messages });
}

/** A message's text parts (plain and HTML), decoded. */
function texts(part, out) {
  if (!part) return out;
  if (/^text\/(plain|html)/.test(part.mimeType || '') && part.body && part.body.data) {
    var d = part.body.data;
    out.push(Utilities.newBlob(typeof d === 'string' ? Utilities.base64DecodeWebSafe(d) : d).getDataAsString());
  }
  (part.parts || []).forEach(function (p) { texts(p, out); });
  return out;
}

function sha256(s) {
  return Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, s, Utilities.Charset.UTF_8)
    .map(function (b) { return ('0' + (b & 255).toString(16)).slice(-2); }).join('');
}

function reply(o) {
  return ContentService.createTextOutput(JSON.stringify(o)).setMimeType(ContentService.MimeType.JSON);
}
