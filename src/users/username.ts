export const USERNAME_MAX_LENGTH = 30;

const BASE_MAX_LENGTH = USERNAME_MAX_LENGTH - 7;

export function usernameBaseFromEmail(email: string): string {
  const localPart = email.split('@')[0].split('+')[0];
  const cleaned = localPart
    .toLowerCase()
    .replace(/[^a-z0-9_.]/g, '')
    .slice(0, BASE_MAX_LENGTH);

  return cleaned.length >= 3 ? cleaned : `user${cleaned}`;
}