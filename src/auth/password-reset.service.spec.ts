import { BadRequestException, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as argon2 from 'argon2';
import { Role, User } from '../generated/prisma/client';
import { MailService } from '../mail/mail.service';
import { PrismaService } from '../prisma/prisma.service';
import { UsersService } from '../users/users.service';
import { PasswordResetService } from './password-reset.service';
import { hashToken } from './token-crypto';

const user = {
  id: 'user-1',
  username: 'jendos',
  email: 'jendos@mail.com',
  passwordHash: null,
  role: Role.USER,
  createdAt: new Date(),
  updatedAt: new Date(),
} satisfies User;

const config: Record<string, unknown> = {
  PASSWORD_RESET_TTL_MINUTES: 30,
  FRONTEND_URL: 'http://localhost:5173',
};

// The reset email is sent without await, so let it finish before asserting
const flushPromises = () => new Promise((resolve) => setImmediate(resolve));

describe('PasswordResetService', () => {
  let prisma: {
    passwordResetToken: {
      deleteMany: jest.Mock;
      create: jest.Mock;
      findUnique: jest.Mock;
      updateMany: jest.Mock;
    };
    user: { update: jest.Mock };
    refreshToken: { updateMany: jest.Mock };
    $transaction: jest.Mock;
  };
  let usersService: { findByEmail: jest.Mock };
  let mailService: { send: jest.Mock };
  let service: PasswordResetService;

  beforeEach(() => {
    prisma = {
      passwordResetToken: {
        deleteMany: jest.fn(),
        create: jest.fn(),
        findUnique: jest.fn(),
        updateMany: jest.fn().mockResolvedValue({ count: 1 }),
      },
      user: { update: jest.fn() },
      refreshToken: { updateMany: jest.fn() },
      $transaction: jest.fn((callback: (tx: unknown) => unknown) =>
        callback(prisma),
      ),
    };
    usersService = { findByEmail: jest.fn().mockResolvedValue(user) };
    mailService = { send: jest.fn().mockResolvedValue(undefined) };

    service = new PasswordResetService(
      prisma as unknown as PrismaService,
      usersService as unknown as UsersService,
      mailService as unknown as MailService,
      { getOrThrow: (key: string) => config[key] } as unknown as ConfigService,
    );
  });

  describe('requestReset', () => {
    it('stores a hashed token and emails the link with the raw token', async () => {
      await service.requestReset(user.email);
      await flushPromises();

      expect(prisma.passwordResetToken.deleteMany).toHaveBeenCalledWith({
        where: { userId: user.id, usedAt: null },
      });

      const mail = mailService.send.mock.calls[0][0];
      const token = new URL(mail.text.match(/http\S+/)[0]).searchParams.get(
        'token',
      );
      const saved = prisma.passwordResetToken.create.mock.calls[0][0].data;

      expect(mail.to).toBe(user.email);
      expect(saved.tokenHash).toBe(hashToken(token!));
    });

    it('does nothing for an unknown email', async () => {
      usersService.findByEmail.mockResolvedValue(null);

      await service.requestReset('nobody@mail.com');
      await flushPromises();

      expect(prisma.passwordResetToken.create).not.toHaveBeenCalled();
      expect(mailService.send).not.toHaveBeenCalled();
    });

    it('does not fail when the email cannot be sent, but logs the error', async () => {
      // Replaces the logger output, so the expected error doesn't clutter the test run
      const logError = jest
        .spyOn(Logger.prototype, 'error')
        .mockImplementation(() => undefined);
      mailService.send.mockRejectedValue(new Error('SMTP is down'));

      await expect(service.requestReset(user.email)).resolves.toBeUndefined();
      await flushPromises();

      expect(logError).toHaveBeenCalled();
      logError.mockRestore();
    });
  });

  describe('resetPassword', () => {
    const storedToken = (overrides: object = {}) => ({
      id: 'reset-1',
      userId: user.id,
      expiresAt: new Date(Date.now() + 60_000),
      usedAt: null,
      ...overrides,
    });

    it('sets the new password, marks the token used and logs out everywhere', async () => {
      prisma.passwordResetToken.findUnique.mockResolvedValue(storedToken());

      await service.resetPassword('token', 'NewPassw0rd!');

      const { passwordHash } = prisma.user.update.mock.calls[0][0].data;
      expect(await argon2.verify(passwordHash, 'NewPassw0rd!')).toBe(true);
      expect(prisma.passwordResetToken.updateMany).toHaveBeenCalledWith({
        where: { id: 'reset-1', usedAt: null },
        data: { usedAt: expect.any(Date) },
      });
      expect(prisma.refreshToken.updateMany).toHaveBeenCalledWith({
        where: { userId: user.id, revokedAt: null },
        data: { revokedAt: expect.any(Date) },
      });
    });

    it.each([
      ['unknown', null],
      ['already used', storedToken({ usedAt: new Date() })],
      ['expired', storedToken({ expiresAt: new Date(Date.now() - 1000) })],
    ])('throws 400 for an %s token', async (_case, stored) => {
      prisma.passwordResetToken.findUnique.mockResolvedValue(stored);

      await expect(
        service.resetPassword('token', 'NewPassw0rd!'),
      ).rejects.toThrow(BadRequestException);
      expect(prisma.user.update).not.toHaveBeenCalled();
    });

    it('throws 400 when a parallel request already used the token', async () => {
      prisma.passwordResetToken.findUnique.mockResolvedValue(storedToken());
      prisma.passwordResetToken.updateMany.mockResolvedValue({ count: 0 });

      await expect(
        service.resetPassword('token', 'NewPassw0rd!'),
      ).rejects.toThrow('Reset link is invalid or expired');
      expect(prisma.user.update).not.toHaveBeenCalled();
    });
  });});