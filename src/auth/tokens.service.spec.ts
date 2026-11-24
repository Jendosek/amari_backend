import { UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { Role, User } from '../generated/prisma/client';
import { PrismaService } from '../prisma/prisma.service';
import { hashToken } from './token-crypto';
import { JwtPayload, TokensService } from './tokens.service';

const user = {
  id: 'user-1',
  username: 'jendos',
  email: 'jendos@mail.com',
  passwordHash: null,
  role: Role.USER,
  createdAt: new Date(),
  updatedAt: new Date(),
} satisfies User;

const DAY_MS = 24 * 60 * 60 * 1000;

describe('TokensService', () => {
  let prisma: {
    refreshToken: {
      create: jest.Mock;
      findUnique: jest.Mock;
      updateMany: jest.Mock;
      deleteMany: jest.Mock;
    };
    $transaction: jest.Mock;
  };
  let jwt: JwtService;
  let service: TokensService;

  beforeEach(() => {
    prisma = {
      refreshToken: {
        create: jest.fn(),
        findUnique: jest.fn(),
        updateMany: jest.fn().mockResolvedValue({ count: 1 }),
        deleteMany: jest.fn(),
      },
      // Runs the callback with the same mock, as if it were a transaction client
      $transaction: jest.fn((callback: (tx: unknown) => unknown) =>
        callback(prisma),
      ),
    };
    // Real JwtService: we want to check a real signed token
    jwt = new JwtService({
      secret: 'test-secret',
      signOptions: { expiresIn: 900 },
    });
    const config = { getOrThrow: jest.fn().mockReturnValue(30) };

    service = new TokensService(
      prisma as unknown as PrismaService,
      jwt,
      config as unknown as ConfigService,
    );
  });

  describe('signAccessToken', () => {
    it('puts only the user id and role into the token', async () => {
      const token = await service.signAccessToken(user);
      const payload = jwt.verify<JwtPayload & { exp: number; iat: number }>(
        token,
      );

      expect(payload.sub).toBe(user.id);
      expect(payload.role).toBe(Role.USER);
      expect(payload.exp - payload.iat).toBe(900);
    });
  });

  describe('issueRefreshToken', () => {
    it('stores only the hash of the token, valid for 30 days', async () => {
      const { token, expiresAt } = await service.issueRefreshToken(user.id);

      const saved = prisma.refreshToken.create.mock.calls[0][0].data;
      expect(saved.tokenHash).toBe(hashToken(token));
      expect(saved.tokenHash).not.toBe(token);
      expect(expiresAt.getTime() - Date.now()).toBeGreaterThan(29 * DAY_MS);
    });
  });

  describe('rotateRefreshToken', () => {
    const storedToken = (overrides: object = {}) => ({
      id: 'token-1',
      userId: user.id,
      expiresAt: new Date(Date.now() + DAY_MS),
      revokedAt: null,
      user,
      ...overrides,
    });

    it('revokes the old token and issues a new one', async () => {
      prisma.refreshToken.findUnique.mockResolvedValue(storedToken());

      const result = await service.rotateRefreshToken('old-token');

      expect(prisma.refreshToken.updateMany).toHaveBeenCalledWith({
        where: { id: 'token-1', revokedAt: null },
        data: { revokedAt: expect.any(Date) },
      });
      expect(prisma.refreshToken.create).toHaveBeenCalled();
      expect(result.user).toBe(user);
      expect(result.refreshToken.token).not.toBe('old-token');
    });

    it('throws 401 for an unknown token', async () => {
      prisma.refreshToken.findUnique.mockResolvedValue(null);

      await expect(service.rotateRefreshToken('unknown')).rejects.toThrow(
        UnauthorizedException,
      );
    });

    it('throws 401 for an expired token', async () => {
      prisma.refreshToken.findUnique.mockResolvedValue(
        storedToken({ expiresAt: new Date(Date.now() - 1000) }),
      );

      await expect(service.rotateRefreshToken('expired')).rejects.toThrow(
        'Refresh token expired',
      );
    });

    it('revokes all user sessions when a revoked token is reused', async () => {
      prisma.refreshToken.findUnique.mockResolvedValue(
        storedToken({ revokedAt: new Date() }),
      );

      await expect(service.rotateRefreshToken('reused')).rejects.toThrow(
        'Refresh token reuse detected',
      );
      expect(prisma.refreshToken.updateMany).toHaveBeenCalledWith({
        where: { userId: user.id, revokedAt: null },
        data: { revokedAt: expect.any(Date) },
      });
    });

    it('throws 401 when a parallel request already rotated the token', async () => {
      prisma.refreshToken.findUnique.mockResolvedValue(storedToken());
      prisma.refreshToken.updateMany.mockResolvedValue({ count: 0 });

      await expect(service.rotateRefreshToken('raced')).rejects.toThrow(
        'Refresh token reuse detected',
      );
      expect(prisma.refreshToken.create).not.toHaveBeenCalled();
    });
  });

  describe('deleteRefreshToken', () => {
    it('deletes the token by its hash', async () => {
      await service.deleteRefreshToken('some-token');

      expect(prisma.refreshToken.deleteMany).toHaveBeenCalledWith({
        where: { tokenHash: hashToken('some-token') },
      });
    });
  });
});