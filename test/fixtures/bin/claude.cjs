// A stand-in for Claude Code (bin/claude runs it): logs how it was run to ~/claude-calls.jsonl, then streams a session.
// Like the real one, its tool commands run detached (a process group of their own). A prompt with SLOW keeps it running,
// with a `sleep 317` started the way its Bash tool would; one with --strict-mcp-config is a listing run; one whose login
// (~/claude-auth.json) is `limited` stops at the usage limit.
const fs = require('fs');
const args = process.argv.slice(2);
let input = '';
process.stdin.on('data', (d) => (input += d));
process.stdin.on('end', () => {
  fs.appendFileSync(process.env.HOME + '/claude-calls.jsonl', JSON.stringify({ args, cwd: process.cwd(), prompt: input, env: Object.keys(process.env).filter((k) => k.startsWith('GLOW_')) }) + '\n');
  const sid = args[args.indexOf(args.includes('--resume') ? '--resume' : '--session-id') + 1];
  const out = (o) => process.stdout.write(JSON.stringify(o) + '\n');
  if (args.includes('--strict-mcp-config')) {
    // a listing run: its helper hands a password to the runner (the socket in its MCP config), then a page shows it
    const sock = JSON.parse(fs.readFileSync(args[args.indexOf('--mcp-config') + 1], 'utf8')).mcpServers['glow-sites'].env.GLOW_SITES_SOCKET;
    const secret = 'Zq9x' + 'Kp7w'.repeat(4);
    const c = require('net').createConnection(sock);
    c.on('connect', () => c.write(JSON.stringify({ mask: secret }) + '\n'));
    c.once('data', () => {
      c.end();
      out({ type: 'system', subtype: 'init', session_id: sid, cwd: process.cwd(), model: 'claude-opus-5-5' });
      out({ type: 'assistant', message: { id: 'm1', content: [{ type: 'text', text: 'Pasted ' + secret }, { type: 'tool_use', id: 't1', name: 'mcp__glow-browser__browser_snapshot', input: {} }] } });
      out({ type: 'user', message: { content: [{ type: 'tool_result', tool_use_id: 't1', content: 'textbox "Pw" [ref=e3]: ' + secret }] } });
      out({ type: 'result', subtype: 'success', is_error: false, result: 'uneed.best: made. The page showed ' + secret, num_turns: 1, total_cost_usd: 0.01 });
    });
    return;
  }
  // Its login (~/claude-auth.json) at its usage limit: Claude Code 2.1's words, then a result that doesn't say error and
  // exit 1, as a session waiting on its subagents ended on 2026-11-09.
  if (fs.existsSync(process.env.HOME + '/claude-auth.json') && JSON.parse(fs.readFileSync(process.env.HOME + '/claude-auth.json', 'utf8')).limited) {
    const said = 'You’ve hit your limit · resets 10pm (America/Los_Angeles)';
    out({ type: 'system', subtype: 'init', session_id: sid, cwd: process.cwd(), model: 'claude-opus-5-5' });
    out({ type: 'assistant', error: 'rate_limit', message: { id: 'm0', content: [{ type: 'text', text: said }] } });
    out({ type: 'result', subtype: 'success', is_error: false, result: said, num_turns: 1 });
    process.exitCode = 1;
    return;
  }
  // A bundle's tasks (its prompt's "===== Task k of n" lines), remembered for its session as Claude Code would: its reply
  // then has a "## Task k" part for each.
  const kept = process.env.HOME + '/claude-tasks-' + sid;
  const tasks = Number(/===== Task \d+ of (\d+) =====/.exec(input)?.[1] ?? (fs.existsSync(kept) ? fs.readFileSync(kept, 'utf8') : 0));
  if (tasks) fs.writeFileSync(kept, String(tasks));
  const reply = tasks ? `One pull request for all: https://github.com/winding-labs/zest/pull/7\n\n${Array.from({ length: tasks }, (_, k) => `## Task ${k + 1}\nDid task ${k + 1}.`).join('\n\n')}` : 'Listed the files. key sk-ant-api03-' + 'z'.repeat(40);
  out({ type: 'system', subtype: 'init', session_id: sid, cwd: process.cwd(), model: 'claude-opus-5-5' });
  out({ type: 'assistant', message: { id: 'm1', usage: { input_tokens: 5, cache_creation_input_tokens: 1000, cache_read_input_tokens: 20000, output_tokens: 40 }, content: [{ type: 'text', text: 'Looking.' }, { type: 'tool_use', id: 't1', name: 'Bash', input: { command: 'PGPASSWORD=Hunter2024x psql -h db.internal ' + process.env.HOME + '/x --token=' + 'sk-ant-api03-' + 'q'.repeat(40) } }] } });
  out({ type: 'rate_limit_event', rate_limit_info: { status: 'allowed', rateLimitType: 'seven_day', unifiedWindows: { seven_day: { utilization: 0.47, status: 'allowed' } } } });
  out({ type: 'user', message: { content: [{ type: 'tool_result', tool_use_id: 't1', content: 'PGPASSWORD=Hunter2024x\n' + 'row '.repeat(400) }] } });
  out('not json, then ' + '{"type":"assistant","message":{"content":"oops"}}');
  if (input.includes('SLOW')) {
    require('child_process').spawn('sleep', ['317'], { detached: true, stdio: 'ignore' });
    return setInterval(() => {}, 1000);
  }
  setTimeout(() => {
    out({ type: 'assistant', message: { id: 'm2', content: [{ type: 'tool_use', name: 'Read', input: { file_path: process.cwd() + '/README.md' } }] } });
    out({ type: 'result', subtype: 'success', is_error: false, result: reply, num_turns: 3, total_cost_usd: 0.05, permission_denials: [{ tool_name: 'Write' }],
      usage: { input_tokens: 10, cache_creation_input_tokens: 1000, cache_read_input_tokens: 40000, output_tokens: 300 }, modelUsage: { 'claude-opus-5-5': { contextWindow: 1000000 } } });
  }, 20);
});
