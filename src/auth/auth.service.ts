import {
  ConflictException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import * as argon2 from 'argon2';
import { Prisma, User } from '../generated/prisma/client';
import { UserResponseDto } from '../users/dto/user-response.dto';
import { UsersService } from '../users/users.service';
import { AuthResponseDto } from './dto/auth-response';
import { LoginDto } from './dto/login.dto';
import { RegisterDto } from './dto/register.dto';
import { IssuedRefreshToken, TokensService } from './tokens.service';

// What the service returns to the controller: the response body
// plus the refresh token, which the controller puts into a cookie
export interface AuthSession {
  body: AuthResponseDto;
  refreshToken: IssuedRefreshToken;
}

@Injectable()
export class AuthService {
  constructor(
    private readonly usersService: UsersService,
    private readonly tokensService: TokensService,
  ) {}

  async register(dto: RegisterDto): Promise<AuthSession> {
    if (await this.usersService.findByEmail(dto.email)) {
      throw new ConflictException('Email is already registered');
    }
    if (await this.usersService.findByUsername(dto.username)) {
      throw new ConflictException('Username is already taken');
    }

    const passwordHash = await argon2.hash(dto.password);

    let user: User;
    try {
      user = await this.usersService.create({
        username: dto.username,
        email: dto.email,
        passwordHash,
      });
    } catch (error) {
      // Two simultaneous requests can both pass the checks above;
      // the unique index in the DB is the final guard
      if (
        error instanceof Prisma.PrismaClientKnownRequestError &&
        error.code === 'P2002'
      ) {
        throw new ConflictException('Email or username is already taken');
      }
      throw error;
    }

    return this.createSession(user);
  }

  async login(dto: LoginDto): Promise<AuthSession> {
    const user = await this.usersService.findByEmail(dto.email);

    // Same error for unknown email, wrong password and Google-only accounts,
    // so the response doesn't reveal which part was wrong
    const isValid =
      user?.passwordHash != null &&
      (await argon2.verify(user.passwordHash, dto.password));

    if (!user || !isValid) {
      throw new UnauthorizedException('Invalid email or password');
    }

    return this.createSession(user);
  }

  private async createSession(user: User): Promise<AuthSession> {
    const [accessToken, refreshToken] = await Promise.all([
      this.tokensService.signAccessToken(user),
      this.tokensService.issueRefreshToken(user.id),
    ]);

    return {
      body: { accessToken, user: UserResponseDto.fromEntity(user) },
      refreshToken,
    };
  }
}