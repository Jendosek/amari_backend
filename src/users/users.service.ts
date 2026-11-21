import { Injectable } from '@nestjs/common';
import { User } from '../generated/prisma/client';
import { PrismaService } from '../prisma/prisma.service';

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

  // Store and look up email/username in lowercase so uniqueness is case-insensitive
  private normalize(value: string): string {
    return value.trim().toLowerCase();
  }
}