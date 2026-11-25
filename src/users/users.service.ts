import { Injectable } from '@nestjs/common';
import { randomInt } from 'node:crypto';
import { User } from '../generated/prisma/client';
import { PrismaService } from '../prisma/prisma.service';
import { usernameBaseFromEmail } from './username';

export interface CreateUserData {
  username: string;
  email: string;
  passwordHash?: string | null;
}

@Injectable()
export class UsersService {
  constructor(private readonly prisma: PrismaService) {}

  findById(id: string): Promise<User | null> {
    return this.prisma.user.findUnique({ where: { id } });
  }

  findByEmail(email: string): Promise<User | null> {
    return this.prisma.user.findUnique({
      where: { email: this.normalize(email) },
    });
  }

  findByUsername(username: string): Promise<User | null> {
    return this.prisma.user.findUnique({
      where: { username: this.normalize(username) },
    });
  }

  create(data: CreateUserData): Promise<User> {
    return this.prisma.user.create({
      data: {
        username: this.normalize(data.username),
        email: this.normalize(data.email),
        passwordHash: data.passwordHash ?? null,
      },
    });
  }

  async generateUniqueUsername(email: string): Promise<string> {
    const base = usernameBaseFromEmail(email);
    if (!(await this.findByUsername(base))) {
      return base;
    }

    for (const digits of [4, 4, 4, 6, 6, 6]) {
      const suffix = randomInt(10 ** (digits - 1), 10 ** digits);
      const candidate = `${base}_${suffix}`;
      if (!(await this.findByUsername(candidate))) {
        return candidate;
      }
    }

    throw new Error(`Could not generate a unique username for ${email}`);
  }

  private normalize(value: string): string {
    return value.trim().toLowerCase();
  }
}