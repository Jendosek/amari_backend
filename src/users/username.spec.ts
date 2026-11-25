import { USERNAME_MAX_LENGTH, usernameBaseFromEmail } from './username';

describe('usernameBaseFromEmail', () => {
  it.each([
    ['jendos@gmail.com', 'jendos'],
    ['Jen.Dos@gmail.com', 'jen.dos'],
    ['jendos+shop@gmail.com', 'jendos'],
    ['jen-dos_99@gmail.com', 'jendos_99'],
    ['ab@gmail.com', 'userab'],
    ['жека@gmail.com', 'user'],
  ])('%s -> %s', (email, expected) => {
    expect(usernameBaseFromEmail(email)).toBe(expected);
  });

  it('leaves room for a numeric suffix in long names', () => {
    const base = usernameBaseFromEmail(`${'a'.repeat(50)}@gmail.com`);

    expect(`${base}_123456`.length).toBeLessThanOrEqual(USERNAME_MAX_LENGTH);
  });
});