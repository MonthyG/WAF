import { NextResponse } from 'next/server';
import {
  apiURL,
  cookieName,
  cookieOptions,
  readBody,
  seal,
  validOrigin,
} from '../../../lib/session';
export const runtime = 'nodejs';
export async function POST(request: Request) {
  if (!validOrigin(request))
    return NextResponse.json(
      { error: { message: 'Request origin is not allowed' } },
      { status: 403 },
    );
  try {
    const body = JSON.parse(await readBody(request, 8192));
    if (typeof body.token !== 'string' || !body.token.trim() || body.token.length > 2048)
      return NextResponse.json(
        { error: { message: 'Enter a project-scoped Keystone token (maximum 2048 characters)' } },
        { status: 400 },
      );
    const response = await fetch(apiURL('sites'), {
      headers: { 'X-Auth-Token': body.token },
      cache: 'no-store',
      redirect: 'error',
      signal: AbortSignal.timeout(10000),
    });
    if (!response.ok)
      return NextResponse.json(
        {
          error: {
            message:
              response.status === 401
                ? 'The token is invalid or expired'
                : 'Unable to validate the session',
          },
        },
        { status: response.status === 401 ? 401 : 503 },
      );
    const result = NextResponse.json(
      { authenticated: true },
      { headers: { 'Cache-Control': 'no-store' } },
    );
    result.cookies.set(cookieName, seal(body.token), cookieOptions());
    return result;
  } catch {
    return NextResponse.json(
      { error: { message: 'Sign-in is unavailable. Check the console and API configuration.' } },
      { status: 503 },
    );
  }
}
export async function DELETE(request: Request) {
  if (!validOrigin(request)) return new Response(null, { status: 403 });
  const result = new NextResponse(null, { status: 204 });
  result.cookies.set(cookieName, '', { ...cookieOptions(), maxAge: 0 });
  return result;
}
