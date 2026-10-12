import { NextResponse } from 'next/server';
import { apiURL, readBody, token, validOrigin } from '../../../../lib/session';
export const runtime = 'nodejs';
const uuid = '[0-9a-fA-F-]{36}';
const allowed = new RegExp(
  `^(usage|sites(?:/${uuid}(?:/verify|/origins(?:/${uuid})?|/metrics|/events(?:/[A-Za-z0-9_-]{1,128}/exclude)?)?)?|policies(?:/${uuid}(?:/rules(?:/${uuid})?)?)?|certificates(?:/${uuid})?|nodes(?:/${uuid}/drain)?)$`,
);
async function proxy(request: Request, context: { params: Promise<{ path: string[] }> }) {
  if (request.method !== 'GET' && !validOrigin(request))
    return NextResponse.json(
      { error: { message: 'Request origin is not allowed' } },
      { status: 403 },
    );
  const session = await token();
  if (!session)
    return NextResponse.json({ error: { message: 'Sign in to continue' } }, { status: 401 });
  const path = (await context.params).path.join('/');
  if (!allowed.test(path)) return new Response(null, { status: 404 });
  try {
    const target = apiURL(path);
    target.search = new URL(request.url).search;
    const response = await fetch(target, {
      method: request.method,
      headers: { 'X-Auth-Token': session, 'Content-Type': 'application/json' },
      body: request.method === 'GET' ? undefined : await readBody(request),
      cache: 'no-store',
      redirect: 'error',
      signal: AbortSignal.timeout(15000),
    });
    return new Response(response.body, {
      status: response.status,
      headers: {
        'Content-Type': response.headers.get('content-type') ?? 'application/json',
        'Cache-Control': 'no-store',
      },
    });
  } catch {
    return NextResponse.json(
      { error: { message: 'The WAF service is unavailable. Please retry.' } },
      { status: 503 },
    );
  }
}
export { proxy as GET, proxy as POST, proxy as PATCH, proxy as DELETE };
