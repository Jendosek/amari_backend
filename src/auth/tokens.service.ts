import { Injectable, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { createHash, randomBytes } from 'node:crypto';
import { Role, User } from '../generated/prisma/client';
import { PrismaService } from '../prisma/prisma.service';

export interface JwtPayload {
  sub: string;
  role: Role;
}

export interface IssuedRefreshToken {
  token: string;
  expiresAt: Date;
}

@Injectable()
export class TokensService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly jwt: JwtService,
    private readonly config: ConfigService,
  ) {}

  signAccessToken(user: Pick<User, 'id' | 'role'>): Promise<string> {
    const payload: JwtPayload = { sub: user.id, role: user.role };
    return this.jwt.signAsync(payload);
  }

  async issueRefreshToken(userId: string): Promise<IssuedRefreshToken> {
    const token = randomBytes(64).toString('base64url');
    const expiresAt = this.refreshExpiresAt();

    await this.prisma.refreshToken.create({
      data: { tokenHash: this.hash(token), userId, expiresAt },
    });

    return { token, expiresAt };
  }

  // Exchanges a valid refresh token for a new one; the old one is revoked
  async rotateRefreshToken(
    token: string,
  ): Promise<{ user: User; refreshToken: IssuedRefreshToken }> {
    const stored = await this.prisma.refreshToken.findUnique({
      where: { tokenHash: this.hash(token) },
      include: { user: true },
    });

    if (!stored) {
      throw new UnauthorizedException('Invalid refresh token');
    }

    if (stored.revokedAt) {
      // A revoked token was used again: it was probably stolen,
      // so all sessions of this user are terminated
      await this.revokeAllForUser(stored.userId);
      throw new UnauthorizedException('Refresh token reuse detected');
    }

    if (stored.expiresAt < new Date()) {
      throw new UnauthorizedException('Refresh token expired');
    }

    const newToken = randomBytes(64).toString('base64url');
    const expiresAt = this.refreshExpiresAt();

    await this.prisma.$transaction(async (tx) => {
      // The revokedAt: null condition makes the check atomic:
      // if a parallel request already rotated this token, nothing is updated
      const { count } = await tx.refreshToken.updateMany({
        where: { id: stored.id, revokedAt: null },
        data: { revokedAt: new Date() },
      });
      if (count === 0) {
        throw new UnauthorizedException('Refresh token reuse detected');
      }

      await tx.refreshToken.create({
        data: {
          tokenHash: this.hash(newToken),
          userId: stored.userId,
          expiresAt,
        },
      });
    });

    return {
      user: stored.user,
      refreshToken: { token: newToken, expiresAt },
    };
  }

  // Used on logout: the token is deleted, not revoked, so a stale copy
  // (e.g. from another tab) is just invalid and doesn't trigger reuse detection
  async deleteRefreshToken(token: string): Promise<void> {
    await this.prisma.refreshToken.deleteMany({
      where: { tokenHash: this.hash(token) },
    });
  }

  async revokeAllForUser(userId: string): Promise<void> {
    await this.prisma.refreshToken.updateMany({
      where: { userId, revokedAt: null },
      data: { revokedAt: new Date() },
    });
  }

  private hash(token: string): string {
    return createHash('sha256').update(token).digest('hex');
  }

  private refreshExpiresAt(): Date {
    const days = this.config.getOrThrow<number>('REFRESH_TOKEN_TTL_DAYS');
    return new Date(Date.now() + days * 24 * 60 * 60 * 1000);
  }
}