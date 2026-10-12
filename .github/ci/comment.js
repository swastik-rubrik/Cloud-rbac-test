// Builds and posts the sticky PR comment. Loaded by actions/github-script.
//
// Reads from env: RESULTS (JSON {schema, policy, terraform, plan}), RUN_URL, PLAN_FILE.
// Everything is a pure function except post(), so build() can be run with plain node.

const MARKER = '<!-- rbac-pr-validation -->';
const LIMIT = 65536;
const ICON = { success: '✅', failure: '❌', cancelled: '⚪', skipped: '⏭️' };

// A code fence longer than any backtick run inside the text, so plan output can't break out.
const fence = (text) => '`'.repeat(Math.max(3, ...(text.match(/`+/g) || []).map((m) => m.length + 1)));

function build({ results, planText, runUrl }) {
  const row = (name, key) => `| ${name} | ${ICON[results[key]] || '❔'} ${results[key] || 'skipped'} |`;
  const blocking = ['schema', 'policy'].filter((k) => results[k] === 'failure');

  const verdict = blocking.length
    ? `❌ **Blocked:** ${blocking.join(' and ')} check failed. See the failing job for findings.`
    : results.plan === 'failure'
      ? '⚠️ Checks passed but the plan failed. This will not apply as-is.'
      : '✅ All checks passed.';

  const head = [
    MARKER, '## Cloud RBAC: PR validation', verdict, '',
    '| Check | Result |', '|---|---|',
    row('Schema validation', 'schema'), row('Policy check', 'policy'),
    row('Terraform lint & validate', 'terraform'), row('Terraform plan', 'plan'), '',
  ].join('\n');
  const foot = `\n<sub>[Workflow run](${runUrl})</sub>\n`;

  let body = '';
  if (planText) {
    const summary = (planText.match(/^(Plan:|No changes\.).*$/m) || [results.plan === 'failure' ? 'plan failed' : 'see output'])[0];
    const room = LIMIT - head.length - foot.length - 400;
    let text = planText.trim();
    if (text.length > room) {
      text = text.slice(0, room).replace(/\n[^\n]*$/, '') +
        `\n\n... truncated (${planText.length.toLocaleString()} chars). Full log: ${runUrl}`;
    }
    const f = fence(text);
    body = [
      '### Plan preview',
      `<details${results.plan === 'failure' ? ' open' : ''}>`,
      `<summary>${summary}</summary>`, '', `${f}hcl`, text, f, '</details>',
    ].join('\n');
  }
  return head + body + foot;
}

async function post({ github, context }) {
  const fs = require('fs');
  const results = JSON.parse(process.env.RESULTS);
  const planFile = process.env.PLAN_FILE;
  const planText = planFile && fs.existsSync(planFile) ? fs.readFileSync(planFile, 'utf8') : '';
  const body = build({ results, planText, runUrl: process.env.RUN_URL });

  require('fs').appendFileSync(process.env.GITHUB_STEP_SUMMARY, body);

  const { owner, repo } = context.repo;
  const issue_number = context.issue.number;
  const comments = await github.paginate(github.rest.issues.listComments, { owner, repo, issue_number, per_page: 100 });
  const existing = comments.find((c) => c.user.type === 'Bot' && c.body.startsWith(MARKER));
  if (existing) await github.rest.issues.updateComment({ owner, repo, comment_id: existing.id, body });
  else await github.rest.issues.createComment({ owner, repo, issue_number, body });
}

module.exports = { build, post };
