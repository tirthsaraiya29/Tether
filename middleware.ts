// Blocks known AI crawlers/models from site content. robots.txt is advisory;
// this enforces it for the agents that identify themselves.
// Exceptions: the AI summary file, robots.txt itself, sitemap, and the
// submission API (form POSTs come from real users' browsers).
import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';

const AI_AGENTS = [
  'gptbot', 'oai-searchbot', 'chatgpt-user', 'claudebot', 'claude-web',
  'anthropic-ai', 'ccbot', 'google-extended', 'perplexitybot', 'bytespider',
  'amazonbot', 'applebot-extended', 'meta-externalagent', 'meta-externalfetcher',
  'facebookexternalhit/1.1+anthropic', 'diffbot', 'youbot', 'cohere-ai',
  'imagesiftbot', 'omgili', 'omgilibot', 'webto.model', 'timpibot',
  'pangu.bot', 'kangaroo bot', 'scrapy'
];

const ALLOWED = /^\/(ai-summary\.txt|robots\.txt|sitemap\.xml)$/;

export default function middleware(request: NextRequest): NextResponse {
  const ua = (request.headers.get('user-agent') || '').toLowerCase();
  const path = new URL(request.url).pathname;

  if (!ALLOWED.test(path) && AI_AGENTS.some(a => ua.includes(a))) {
    return new NextResponse(
      'AI access is not permitted on this site. Read /ai-summary.txt instead.\n',
      {
        status: 403,
        headers: {
          'Content-Type': 'text/plain; charset=utf-8',
          'X-Robots-Tag': 'noai, noimageai'
        }
      }
    );
  }

  // Pass the request through; add X-Robots-Tag header to the response.
  const response = NextResponse.next();
  response.headers.set('X-Robots-Tag', 'noai, noimageai');
  return response;
}

// Static-file matcher: everything except the explicit allowlist above.
// /api/submit stays reachable so real users can still submit the form.
export const config = {
  matcher: ['/((?!api/|_vercel|favicon|apple-touch-icon|manifest.webmanifest|docs/|ai-summary|robots|sitemap).*)']
};
