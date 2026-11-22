import type { CookieOptions, Response, Request } from 'express';


export const REFRESH_COOKIE_NAME = 'refresh_token';

// The cookie is sent by the browser only to /api/v1/auth/* endpoints
const REFRESH_COOKIE_PATH = '/api/v1/auth';

function baseOptions(secure: boolean): CookieOptions {
  return {
    httpOnly: true,
    secure,
    sameSite: 'lax',
    path: REFRESH_COOKIE_PATH,
  };
}

export function setRefreshCookie(
  res: Response,
  token: string,
  expiresAt: Date,
  secure: boolean,
): void {
  res.cookie(REFRESH_COOKIE_NAME, token, {
    ...baseOptions(secure),
    expires: expiresAt,
  });
}

export function clearRefreshCookie(res: Response, secure: boolean): void {
  res.clearCookie(REFRESH_COOKIE_NAME, baseOptions(secure));
}

export function getRefreshCookie(req: Request): string | undefined {
  const value: unknown = req.cookies?.[REFRESH_COOKIE_NAME];
  return typeof value === 'string' && value.length > 0 ? value : undefined;
}