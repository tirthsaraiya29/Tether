// Tether website submission endpoint (Vercel serverless).
// Creates public GitHub issues for bug/feature/appreciation submissions and
// stores contact details privately. Security reports never become public issues.
//
// Required environment variables (set in Vercel project settings, never committed):
//   GITHUB_TOKEN        — fine-grained token with "Issues: Read & write" on Tether
//   PRIVATE_REPO_TOKEN  — (optional) token with repo scope on the private contacts repo;
//                         falls back to GITHUB_TOKEN if unset
//   CONTACTS_REPO       — (optional) private repo for contact storage,
//                         default "tirthsaraiya29/tether-submissions" (must be private)

const REPO = 'tirthsaraiya29/Tether';
const API = 'https://api.github.com';

const MAX_FIELD = 10000;
const MAX_BODY = 200000;

const LABELS = {
  bug: { title: 'Bug', label: 'bug' },
  feature: { title: 'Feature', label: 'enhancement' },
  appreciation: { title: 'Appreciation', label: 'appreciation' }
};

// Simple per-IP rate limiter (per serverless instance; Vercel also fronts this).
const rateMap = new Map();
const RATE_LIMIT = 5;
const RATE_WINDOW_MS = 10 * 60 * 1000;

function json(res, status, obj) {
  res.statusCode = status;
  res.setHeader('Content-Type', 'application/json');
  res.end(JSON.stringify(obj));
}

function cleanStr(v, max = MAX_FIELD) {
  if (typeof v !== 'string') return '';
  // strip control chars except \n\r\t
  return v.replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, '').trim().slice(0, max);
}

function mdEsc(s) {
  // Prevent Markdown/HTML injection into issue bodies: no leading headers/links forgery.
  return s.replace(/^#/gm, '#​').replace(/</g, '&lt;');
}

function checkRate(ip) {
  const now = Date.now();
  const rec = rateMap.get(ip);
  if (!rec || now - rec.start > RATE_WINDOW_MS) {
    rateMap.set(ip, { start: now, n: 1 });
    return { ok: true };
  }
  rec.n += 1;
  if (rec.n > RATE_LIMIT) {
    return { ok: false, retry: Math.ceil((RATE_WINDOW_MS - (now - rec.start)) / 1000) };
  }
  return { ok: true };
}

function ghHeaders(token) {
  return {
    'Authorization': `Bearer ${token}`,
    'Accept': 'application/vnd.github+json',
    'User-Agent': 'tether-website'
  };
}

function buildBody(category, f) {
  const lines = [];
  if (category === 'bug') {
    lines.push('### Affected component', f.component || '_not provided_', '');
    lines.push('### Describe the bug', mdEsc(f.description), '');
    lines.push('### Steps to reproduce', mdEsc(f.reproduce), '');
    lines.push('### Expected behaviour', mdEsc(f.expected), '');
    lines.push('### Actual behaviour', mdEsc(f.actual), '');
    lines.push('### Tether version or commit', f.version || '_not provided_', '');
    lines.push('### Android environment', f.androidEnv || '_not provided_', '');
    lines.push('### Windows environment', f.windowsEnv || '_not provided_', '');
    lines.push('### Logs and screenshots', mdEsc(f.logs || '_not provided_'), '');
    lines.push('### Additional context', mdEsc(f.additional || '_not provided_'), '');
    lines.push('_Submitted via the Tether website Ask a Question form._');
  } else if (category === 'feature') {
    lines.push('### Problem or use case', mdEsc(f.problem), '');
    lines.push('### Proposed solution', mdEsc(f.solution), '');
    lines.push('### Relevant component', f.component || '_not provided_', '');
    lines.push('### Alternatives considered', mdEsc(f.alternatives || '_not provided_'), '');
    lines.push('### Additional context', mdEsc(f.context || '_not provided_'), '');
    lines.push('_Submitted via the Tether website Ask a Question form._');
  } else {
    lines.push('### Your message', mdEsc(f.message), '');
    lines.push('### Suggestions or feedback', mdEsc(f.feedback || '_not provided_'), '');
    lines.push('### Acknowledgements', f.ack ? '- [x] No passwords, private keys, tokens, or other sensitive information included.' : '- [ ] (missing)', '');
    lines.push('_Submitted via the Tether website Ask a Question form._');
  }
  return lines.join('\n').slice(0, MAX_BODY);
}

// Contact details go ONLY here — a private repo owned by the maintainer.
async function storeContact(ref, email, phone, token, contactsRepo) {
  const content = Buffer.from(
    JSON.stringify({ ref, email: email || null, phone: phone || null, at: new Date().toISOString() }, null, 2)
  ).toString('base64');
  const res = await fetch(`${API}/repos/${contactsRepo}/contents/${ref}.json`, {
    method: 'PUT',
    headers: { ...ghHeaders(token), 'Content-Type': 'application/json' },
    body: JSON.stringify({
      message: `Contact info for submission ${ref}`,
      content,
      // secret-ish files; not a real secret but keep it out of diffs by default branch visibility
      branch: 'contacts'
    })
  });
  if (!res.ok && res.status !== 422) { // 422 = already exists, fine
    throw new Error(`contact store failed: ${res.status}`);
  }
}

module.exports = async (req, res) => {
  if (req.method !== 'POST') {
    return json(res, 405, { ok: false, error: 'Method not allowed' });
  }

  const token = process.env.GITHUB_TOKEN;
  if (!token) {
    return json(res, 503, { ok: false, error: 'Submission service is not configured yet. Please report issues on GitHub directly.' });
  }

  const ip = (req.headers['x-forwarded-for'] || 'unknown').split(',')[0].trim();
  const rate = checkRate(ip);
  if (!rate.ok) {
    return json(res, 429, { ok: false, error: 'Too many submissions. Please wait before trying again.', retry_after: rate.retry });
  }

  let body;
  try {
    const raw = await new Promise((resolve, reject) => {
      let data = '';
      req.on('data', c => {
        data += c;
        if (data.length > MAX_BODY) { reject(new Error('too large')); req.destroy(); }
      });
      req.on('end', () => resolve(data));
      req.on('error', reject);
    });
    body = JSON.parse(raw);
  } catch (e) {
    return json(res, 400, { ok: false, error: 'Invalid request.' });
  }

  const category = cleanStr(body.category, 20);
  const honeypot = cleanStr(body.website, 100);
  if (honeypot) return json(res, 200, { ok: true }); // bot: pretend success, do nothing
  if (body._ts && Date.now() - Number(body._ts) < 3000) {
    return json(res, 400, { ok: false, error: 'Submission rejected.' }); // too-fast: likely bot
  }

  const fields = body.fields && typeof body.fields === 'object' ? body.fields : {};
  const f = {};
  for (const k of Object.keys(fields)) f[cleanStr(k, 40)] = cleanStr(fields[k]);

  const email = cleanStr(body.contact_email, 200);
  const phone = cleanStr(body.contact_phone, 30);
  if (!email && !phone) {
    return json(res, 400, { ok: false, error: 'Contact information (email or phone) is required.' });
  }

  const ref = `sub-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
  const contactsRepo = process.env.CONTACTS_REPO || 'tirthsaraiya29/tether-submissions';

  try {
    // ---- Security vulnerabilities: private only, never a public issue ----
    if (category === 'security') {
      if (f.ack !== true) {
        return json(res, 400, { ok: false, error: 'You must acknowledge confidential handling.' });
      }
      await storeContact(ref, email, phone, process.env.PRIVATE_REPO_TOKEN || token, contactsRepo);
      const detail = [
        `Ref: ${ref}`,
        `Affected component: ${f.component || 'unspecified'}`,
        `Reproducible: ${f.reproducible || 'unspecified'}`,
        `Previously disclosed: ${f.disclosed || 'unspecified'}`,
        '',
        '### Description',
        mdEsc(f.description || 'not provided'),
        '',
        '### Impact',
        mdEsc(f.impact || 'not provided'),
        '',
        '### Reproduction / evidence',
        mdEsc(f.reproduce || 'not provided')
      ].join('\n');
      // Persist the report itself in the private repo (never in Tether's public issues).
      const reportB64 = Buffer.from(detail).toString('base64');
      const saved = await fetch(`${API}/repos/${contactsRepo}/contents/${ref}-report.md`, {
        method: 'PUT',
        headers: { ...ghHeaders(process.env.PRIVATE_REPO_TOKEN || token), 'Content-Type': 'application/json' },
        body: JSON.stringify({ message: `Security report ${ref}`, content: reportB64, branch: 'contacts' })
      });
      if (!saved.ok && saved.status !== 422) throw new Error(`security report store failed: ${saved.status}`);
      // Optional: also create a draft private advisory via the repo security-advisories API.
      // GitHub's REST API for repository security advisories requires Enterprise Cloud; if unavailable,
      // the private repo copy above is the handoff. The maintainer can promote it at:
      // https://github.com/tirthsaraiya29/Tether/security/advisories/new
      return json(res, 200, { ok: true, reference: ref });
    }

    // ---- Public categories: create a GitHub issue ----
    const tpl = LABELS[category];
    if (!tpl) return json(res, 400, { ok: false, error: 'Unknown submission category.' });

    const titleGuess = f.description || f.problem || f.message || '';
    const title = `[${tpl.title}]: ${titleGuess.split('\n')[0].slice(0, 80) || ref}`;
    const issueBody = buildBody(category, f);

    const created = await fetch(`${API}/repos/${REPO}/issues`, {
      method: 'POST',
      headers: { ...ghHeaders(token), 'Content-Type': 'application/json' },
      body: JSON.stringify({ title, body: issueBody, labels: [tpl.label] })
    });
    if (!created.ok) {
      const errText = await created.text();
      console.error(`issue creation failed: ${created.status} ${errText.slice(0, 300)}`);
      return json(res, 502, { ok: false, error: 'Could not create the issue on GitHub. Please try again shortly.' });
    }
    const issue = await created.json();

    // Store contact details privately, associated with the issue number.
    try {
      await storeContact(`issue-${issue.number}`, email, phone, process.env.PRIVATE_REPO_TOKEN || token, contactsRepo);
    } catch (e) {
      console.error(`contact storage failed for issue ${issue.number}: ${e.message}`);
      // Issue exists; contact association failed. Report success but note it for the maintainer.
      try {
        await fetch(`${API}/repos/${REPO}/issues/${issue.number}/comments`, {
          method: 'POST',
          headers: { ...ghHeaders(token), 'Content-Type': 'application/json' },
          body: JSON.stringify({ body: `⚠️ Private contact storage failed (ref ${ref}). Contact details were NOT published.` })
        });
      } catch (_) { /* best effort */ }
    }

    return json(res, 200, { ok: true, number: issue.number, url: issue.html_url });
  } catch (e) {
    console.error(`submit error: ${e.message}`);
    return json(res, 500, { ok: false, error: 'Internal error. Please try again.' });
  }
};
