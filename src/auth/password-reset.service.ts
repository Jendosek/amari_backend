import { BadRequestException, Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as argon2 from 'argon2';
import { User } from '../generated/prisma/client';
import { passwordResetEmail } from '../mail/templates/password-reset.template';
import { MailService } from '../mail/mail.service';
import { PrismaService } from '../prisma/prisma.service';
import { UsersService } from '../users/users.service';
import { generateToken, hashToken } from './token-crypto';

@Injectable()
export class PasswordResetService {
  private readonly logger = new Logger(PasswordResetService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly usersService: UsersService,
    private readonly mailService: MailService,
    private readonly config: ConfigService,
  ) {}

  // Always finishes silently, so the response never reveals
  // whether an account with this email exists
  async requestReset(email: string): Promise<void> {
    const user = await this.usersService.findByEmail(email);
    if (!user) {
      return;
    }

    const token = generateToken(32);
    const ttlMinutes = this.config.getOrThrow<number>(
      'PASSWORD_RESET_TTL_MINUTES',
    );

    // Only the latest link stays valid
    await this.prisma.passwordResetToken.deleteMany({
      where: { userId: user.id, usedAt: null },
    });
    await this.prisma.passwordResetToken.create({
      data: {
        tokenHash: hashToken(token),
        userId: user.id,
        expiresAt: new Date(Date.now() + ttlMinutes * 60 * 1000),
      },
    });

    // Not awaited: sending takes ~1s, and waiting for it would make
    // the response for existing emails noticeably slower than for unknown ones
    void this.sendResetEmail(user, token, ttlMinutes).catch((error) =>
      this.logger.error(`Failed to send reset email to ${user.email}`, error),
    );
  }

  async resetPassword(token: string, newPassword: string): Promise<void> {
    const stored = await this.prisma.passwordResetToken.findUnique({
      where: { tokenHash: hashToken(token) },
    });

    // One message for every case: unknown, already used or expired link
    if (!stored || stored.usedAt || stored.expiresAt < new Date()) {
      throw new BadRequestException('Reset link is invalid or expired');
    }

    const passwordHash = await argon2.hash(newPassword);

    await this.prisma.$transaction(async (tx) => {
      // Atomic "use once": if a parallel request already used the token,
      // nothing is updated and the whole transaction is rolled back
      const { count } = await tx.passwordResetToken.updateMany({
        where: { id: stored.id, usedAt: null },
        data: { usedAt: new Date() },
      });
      if (count === 0) {
        throw new BadRequestException('Reset link is invalid or expired');
      }

      await tx.user.update({
        where: { id: stored.userId },
        data: { passwordHash },
      });

      // Log out everywhere: if the account was compromised,
      // the attacker's sessions stop working too
      await tx.refreshToken.updateMany({
        where: { userId: stored.userId, revokedAt: null },
        data: { revokedAt: new Date() },
      });
    });
  }

  private sendResetEmail(
    user: User,
    token: string,
    ttlMinutes: number,
  ): Promise<void> {
    const frontendUrl = this.config.getOrThrow<string>('FRONTEND_URL');
    const resetUrl = `${frontendUrl}/reset-password?token=${token}`;

    return this.mailService.send(
      passwordResetEmail({
        to: user.email,
        username: user.username,
        resetUrl,
        ttlMinutes,
      }),
    );
  }
}