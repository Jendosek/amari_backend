import { ConflictException, Injectable } from '@nestjs/common';
import * as argon2 from 'argon2';
import { Prisma } from '../generated/prisma/client';
import { UserResponseDto } from '../users/dto/user-response.dto';
import { UsersService } from '../users/users.service';
import { RegisterDto } from './dto/register.dto';

@Injectable()
export class AuthService {
  constructor(private readonly usersService: UsersService) {}

  async register(dto: RegisterDto): Promise<UserResponseDto> {
    if (await this.usersService.findByEmail(dto.email)) {
      throw new ConflictException('Email is already registered');
    }
    if (await this.usersService.findByUsername(dto.username)) {
      throw new ConflictException('Username is already taken');
    }

    const passwordHash = await argon2.hash(dto.password);

    try {
      const user = await this.usersService.create({
        username: dto.username,
        email: dto.email,
        passwordHash,
      });
      return UserResponseDto.fromEntity(user);
    } catch (error) {
      if (
        error instanceof Prisma.PrismaClientKnownRequestError &&
        error.code === 'P2002'
      ) {
        throw new ConflictException('Email or username is already taken');
      }
      throw error;
    }
  }
}