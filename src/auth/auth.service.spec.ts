import { ConflictException, UnauthorizedException } from '@nestjs/common';
import * as argon2 from 'argon2';
import { Prisma, Role, User } from '../generated/prisma/client';
import { UsersService } from '../users/users.service';
import { AuthService } from './auth.service';
import { RegisterDto } from './dto/register.dto';
import { TokensService } from './tokens.service';

const PASSWORD = 'Passw0rd!';

const registerDto: RegisterDto = {
  username: 'jendos',
  email: 'jendos@mail.com',
  password: PASSWORD,
  confirmPassword: PASSWORD,
};

describe('AuthService', () => {
  let user: User;
  let usersService: {
    findByEmail: jest.Mock;
    findByUsername: jest.Mock;
    create: jest.Mock;
  };
  let tokensService: {
    signAccessToken: jest.Mock;
    issueRefreshToken: jest.Mock;
    rotateRefreshToken: jest.Mock;
    deleteRefreshToken: jest.Mock;
  };
  let service: AuthService;

  beforeAll(async () => {
    // Real argon2 hash, so login tests check real password verification
    user = {
      id: 'user-1',
      username: 'jendos',
      email: 'jendos@mail.com',
      passwordHash: await argon2.hash(PASSWORD),
      role: Role.USER,
      createdAt: new Date(),
      updatedAt: new Date(),
    };
  });

  beforeEach(() => {
    usersService = {
      findByEmail: jest.fn().mockResolvedValue(null),
      findByUsername: jest.fn().mockResolvedValue(null),
      create: jest.fn().mockResolvedValue(user),
    };
    tokensService = {
      signAccessToken: jest.fn().mockResolvedValue('access-token'),
      issueRefreshToken: jest.fn().mockResolvedValue({
        token: 'refresh-token',
        expiresAt: new Date(),
      }),
      rotateRefreshToken: jest.fn(),
      deleteRefreshToken: jest.fn(),
    };

    service = new AuthService(
      usersService as unknown as UsersService,
      tokensService as unknown as TokensService,
    );
  });

  describe('register', () => {
    it('creates a user with a hashed password and returns a session', async () => {
      const session = await service.register(registerDto);

      const created = usersService.create.mock.calls[0][0];
      expect(created.passwordHash).not.toBe(PASSWORD);
      expect(await argon2.verify(created.passwordHash, PASSWORD)).toBe(true);

      expect(session.body.accessToken).toBe('access-token');
      expect(session.body.user).not.toHaveProperty('passwordHash');
      expect(session.refreshToken.token).toBe('refresh-token');
    });

    it('throws 409 when the email is already registered', async () => {
      usersService.findByEmail.mockResolvedValue(user);

      await expect(service.register(registerDto)).rejects.toThrow(
        'Email is already registered',
      );
      expect(usersService.create).not.toHaveBeenCalled();
    });

    it('throws 409 when the username is already taken', async () => {
      usersService.findByUsername.mockResolvedValue(user);

      await expect(service.register(registerDto)).rejects.toThrow(
        'Username is already taken',
      );
    });

    it('throws 409 when the DB unique index rejects a parallel duplicate', async () => {
      usersService.create.mockRejectedValue(
        new Prisma.PrismaClientKnownRequestError('Unique constraint failed', {
          code: 'P2002',
          clientVersion: 'test',
        }),
      );

      await expect(service.register(registerDto)).rejects.toThrow(
        ConflictException,
      );
    });
  });

  describe('login', () => {
    it('returns a session for the correct password', async () => {
      usersService.findByEmail.mockResolvedValue(user);

      const session = await service.login({
        email: user.email,
        password: PASSWORD,
      });

      expect(session.body.user.id).toBe(user.id);
      expect(tokensService.issueRefreshToken).toHaveBeenCalledWith(user.id);
    });

    it('throws 401 for a wrong password', async () => {
      usersService.findByEmail.mockResolvedValue(user);

      await expect(
        service.login({ email: user.email, password: 'Wrong1!xx' }),
      ).rejects.toThrow('Invalid email or password');
    });

    it('throws the same 401 for an unknown email', async () => {
      await expect(
        service.login({ email: 'nobody@mail.com', password: PASSWORD }),
      ).rejects.toThrow('Invalid email or password');
    });

    it('throws the same 401 for a Google-only account without a password', async () => {
      usersService.findByEmail.mockResolvedValue({
        ...user,
        passwordHash: null,
      });

      await expect(
        service.login({ email: user.email, password: PASSWORD }),
      ).rejects.toThrow('Invalid email or password');
    });
  });

  describe('refresh', () => {
    it('throws 401 when the cookie is missing', async () => {
      await expect(service.refresh(undefined)).rejects.toThrow(
        UnauthorizedException,
      );
      expect(tokensService.rotateRefreshToken).not.toHaveBeenCalled();
    });

    it('rotates the refresh token and signs a new access token', async () => {
      const newRefresh = { token: 'new-refresh', expiresAt: new Date() };
      tokensService.rotateRefreshToken.mockResolvedValue({
        user,
        refreshToken: newRefresh,
      });

      const session = await service.refresh('old-refresh');

      expect(tokensService.rotateRefreshToken).toHaveBeenCalledWith(
        'old-refresh',
      );
      expect(session.body.accessToken).toBe('access-token');
      expect(session.refreshToken).toBe(newRefresh);
    });
  });

  describe('logout', () => {
    it('deletes the refresh token when the cookie is present', async () => {
      await service.logout('refresh-token');

      expect(tokensService.deleteRefreshToken).toHaveBeenCalledWith(
        'refresh-token',
      );
    });

    it('does nothing when the cookie is missing', async () => {
      await service.logout(undefined);

      expect(tokensService.deleteRefreshToken).not.toHaveBeenCalled();
    });
  });
});