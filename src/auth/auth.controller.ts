import {
  Body,
  Controller,
  HttpCode,
  HttpStatus,
  Post,
  Res,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import {
  ApiBadRequestResponse,
  ApiConflictResponse,
  ApiCreatedResponse,
  ApiOkResponse,
  ApiOperation,
  ApiTags,
  ApiUnauthorizedResponse,
} from '@nestjs/swagger';
import type { Response } from 'express';
import { AuthService, AuthSession } from './auth.service';
import { AuthResponseDto } from './dto/auth-response';
import { LoginDto } from './dto/login.dto';
import { RegisterDto } from './dto/register.dto';
import { setRefreshCookie } from './refresh-cookie';

@ApiTags('auth')
@Controller('auth')
export class AuthController {
  constructor(
    private readonly authService: AuthService,
    private readonly config: ConfigService,
  ) {}

  @Post('register')
  @ApiOperation({ summary: 'Register a new user and log them in' })
  @ApiCreatedResponse({ type: AuthResponseDto })
  @ApiBadRequestResponse({ description: 'Validation failed' })
  @ApiConflictResponse({ description: 'Email or username is already taken' })
  async register(
    @Body() dto: RegisterDto,
    @Res({ passthrough: true }) res: Response,
  ): Promise<AuthResponseDto> {
    const session = await this.authService.register(dto);
    return this.sendSession(res, session);
  }

  @Post('login')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Log in with email and password' })
  @ApiOkResponse({ type: AuthResponseDto })
  @ApiBadRequestResponse({ description: 'Validation failed' })
  @ApiUnauthorizedResponse({ description: 'Invalid email or password' })
  async login(
    @Body() dto: LoginDto,
    @Res({ passthrough: true }) res: Response,
  ): Promise<AuthResponseDto> {
    const session = await this.authService.login(dto);
    return this.sendSession(res, session);
  }

  // Puts the refresh token into an httpOnly cookie and returns the body
  private sendSession(res: Response, session: AuthSession): AuthResponseDto {
    setRefreshCookie(
      res,
      session.refreshToken.token,
      session.refreshToken.expiresAt,
      this.isProduction(),
    );
    return session.body;
  }

  private isProduction(): boolean {
    return this.config.get<string>('NODE_ENV') === 'production';
  }
}