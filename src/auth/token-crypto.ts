import { createHash, randomBytes } from 'node:crypto';

// Random, URL-safe token that is sent to the client (cookie or email link)
export function generateToken(bytes: number): string {
  return randomBytes(bytes).toString('base64url');
}

// Only this hash is stored in the DB. SHA-256 is enough because the token
// itself is random and long, so it can't be brute-forced like a password
export function hashToken(token: string): string {
  return createHash('sha256').update(token).digest('hex');
}