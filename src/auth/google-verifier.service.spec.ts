import { UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { OAuth2Client, TokenPayload } from 'google-auth-library';
import { GoogleVerifier } from './google-verifier.service';

const CLIENT_ID = 'test-client-id.apps.googleusercontent.com';

describe('GoogleVerifier', () => {
  let verifyIdToken: jest.SpyInstance;
  let verifier: GoogleVerifier;

  const mockPayload = (payload: Partial<TokenPayload> | undefined) =>
    verifyIdToken.mockResolvedValue({ getPayload: () => payload });

  beforeEach(() => {
    verifyIdToken = jest.spyOn(OAuth2Client.prototype, 'verifyIdToken');
    verifier = new GoogleVerifier({
      getOrThrow: () => CLIENT_ID,
    } as unknown as ConfigService);
  });

  afterEach(() => {
    verifyIdToken.mockRestore();
  });

  it('returns the Google id and email for a valid token', async () => {
    mockPayload({
      sub: 'google-1',
      email: 'jendos@gmail.com',
      email_verified: true,
    });

    await expect(verifier.verify('id-token')).resolves.toEqual({
      googleId: 'google-1',
      email: 'jendos@gmail.com',
    });
    expect(verifyIdToken).toHaveBeenCalledWith({
      idToken: 'id-token',
      audience: CLIENT_ID,
    });
  });

  it('throws 401 when Google rejects the token', async () => {
    verifyIdToken.mockRejectedValue(new Error('Wrong recipient'));

    await expect(verifier.verify('id-token')).rejects.toThrow(
      UnauthorizedException,
    );
  });

  it('throws 401 when the token has no email', async () => {
    mockPayload({ sub: 'google-1', email_verified: true });

    await expect(verifier.verify('id-token')).rejects.toThrow(
      'Invalid Google token',
    );
  });

  it('throws 401 when the Google email is not verified', async () => {
    mockPayload({
      sub: 'google-1',
      email: 'jendos@gmail.com',
      email_verified: false,
    });

    await expect(verifier.verify('id-token')).rejects.toThrow(
      'Google email is not verified',
    );
  });
});