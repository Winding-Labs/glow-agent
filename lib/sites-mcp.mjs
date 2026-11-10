// The `glow-sites` MCP server (lib/sites.mjs): the runner mounts it on listing runs only, with the brief the Glow phone
// signed (GLOW_SITES_PRODUCT, GLOW_SITES_LIST, GLOW_SITES_EMAIL) and the socket it masks released values through
// (GLOW_SITES_SOCKET), in the MCP config it writes for that run (--strict-mcp-config). Started any other way it serves
// nothing. Speaks MCP on stdin/stdout; never writes a password anywhere but the keychain and the clipboard. brand_file
// asks Glow for the run's brand kit with this computer's key (GLOW_SITES_RUN; the key stays in this process).
import { brandFor, keychainStore, listingOf, macClipboard, mcpServe, relayMail, releaseTo, sitesTools } from './sites.mjs';

const env = process.env;
// The same checks as the brief itself (listingOf), on what the runner handed over.
const brief = listingOf(`Site listings · ${env.GLOW_SITES_PRODUCT ?? ''}\nSites: ${env.GLOW_SITES_LIST ?? ''}${env.GLOW_SITES_EMAIL ? `\nEmail: ${env.GLOW_SITES_EMAIL}` : ''}`);
if (!brief || brief.error || brief.slug !== env.GLOW_SITES_PRODUCT || !env.GLOW_SITES_SOCKET) {
  process.stderr.write('glow-sites: not started by a listing run, so it serves nothing.\n');
  process.exit(1);
}
const store = keychainStore();
const relay = store.mail();
const tools = sitesTools({ ctx: brief, store, clipboard: macClipboard(), release: releaseTo(env.GLOW_SITES_SOCKET), mail: relay ? relayMail({ relay }) : null, brand: brandFor(env) });
await mcpServe({ name: 'glow-sites', tools: tools.tools, call: tools.call });
tools.close();
process.exit(0);
