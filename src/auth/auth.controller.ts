import {
    Body,
    Controller,
    HttpCode,
    HttpStatus,
    Post,
    Req,
    Res,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import {
    ApiBadRequestResponse,
    ApiConflictResponse,
    ApiCreatedResponse,
    ApiNoContentResponse,
    ApiOkResponse,
    ApiOperation,
    ApiTags,
    ApiTooManyRequestsResponse,
    ApiUnauthorizedResponse,
} from '@nestjs/swagger';
import { minutes, Throttle } from '@nestjs/throttler';
import type { Request, Response } from 'express';
import { AuthService, AuthSession } from './auth.service';
import { Public } from './decorators/public.decorator';
import { AuthResponseDto } from './dto/auth-response';
import { ForgotPasswordDto } from './dto/forgot-password.dto';
import { LoginDto } from './dto/login.dto';
import { RegisterDto } from './dto/register.dto';
import { ResetPasswordDto } from './dto/reset-password.dto';
import { PasswordResetService } from './password-reset.service';
import {
    clearRefreshCookie,
    getRefreshCookie,
    setRefreshCookie,
} from './refresh-cookie';
import { GoogleLoginDto } from './dto/google-login.dto';

@ApiTags('auth')
@Public()
@Controller('auth')
export class AuthController {
    constructor(
        private readonly authService: AuthService,
        private readonly passwordResetService: PasswordResetService,
        private readonly config: ConfigService,
    ) { }

    @Post('register')
    @Throttle({ default: { ttl: minutes(1), limit: 3 } })
    @ApiOperation({ summary: 'Register a new user and log them in' })
    @ApiCreatedResponse({ type: AuthResponseDto })
    @ApiBadRequestResponse({ description: 'Validation failed' })
    @ApiConflictResponse({ description: 'Email or username is already taken' })
    @ApiTooManyRequestsResponse({ description: 'Too many registration attempts' })
    async register(
        @Body() dto: RegisterDto,
        @Res({ passthrough: true }) res: Response,
    ): Promise<AuthResponseDto> {
        const session = await this.authService.register(dto);
        return this.sendSession(res, session);
    }

    @Post('login')
    @Throttle({ default: { ttl: minutes(1), limit: 5 } })
    @HttpCode(HttpStatus.OK)
    @ApiOperation({ summary: 'Log in with email and password' })
    @ApiOkResponse({ type: AuthResponseDto })
    @ApiBadRequestResponse({ description: 'Validation failed' })
    @ApiUnauthorizedResponse({ description: 'Invalid email or password' })
    @ApiTooManyRequestsResponse({ description: 'Too many login attempts' })
    async login(
        @Body() dto: LoginDto,
        @Res({ passthrough: true }) res: Response,
    ): Promise<AuthResponseDto> {
        const session = await this.authService.login(dto);
        return this.sendSession(res, session);
    }

    @Post('google')
    @Throttle({ default: { ttl: minutes(1), limit: 10 } })
    @HttpCode(HttpStatus.OK)
    @ApiOperation({
        summary: 'Log in or sign up with a Google ID token',
        description:
            'Creates the user on first login, links an existing account with the same verified email',
    })
    @ApiOkResponse({ type: AuthResponseDto })
    @ApiBadRequestResponse({ description: 'Validation failed' })
    @ApiUnauthorizedResponse({
        description: 'Invalid Google token or unverified Google email',
    })
    @ApiConflictResponse({
        description: 'The account is already linked to another Google account',
    })
    @ApiTooManyRequestsResponse({ description: 'Too many attempts' })
    async googleLogin(
        @Body() dto: GoogleLoginDto,
        @Res({ passthrough: true }) res: Response,
    ): Promise<AuthResponseDto> {
        const session = await this.authService.loginWithGoogle(dto.idToken);
        return this.sendSession(res, session);
    }

    @Post('refresh')
    @HttpCode(HttpStatus.OK)
    @ApiOperation({
        summary: 'Get a new access token using the refresh token cookie',
    })
    @ApiOkResponse({ type: AuthResponseDto })
    @ApiUnauthorizedResponse({
        description: 'Refresh token is missing, invalid, expired or reused',
    })
    async refresh(
        @Req() req: Request,
        @Res({ passthrough: true }) res: Response,
    ): Promise<AuthResponseDto> {
        try {
            const session = await this.authService.refresh(getRefreshCookie(req));
            return this.sendSession(res, session);
        } catch (error) {
            // A rejected refresh token is useless, so remove it from the browser
            clearRefreshCookie(res, this.isProduction());
            throw error;
        }
    }

    @Post('logout')
    @HttpCode(HttpStatus.NO_CONTENT)
    @ApiOperation({ summary: 'Log out from the current device' })
    @ApiNoContentResponse({ description: 'Logged out, cookie cleared' })
    async logout(
        @Req() req: Request,
        @Res({ passthrough: true }) res: Response,
    ): Promise<void> {
        await this.authService.logout(getRefreshCookie(req));
        clearRefreshCookie(res, this.isProduction());
    }

    @Post('forgot-password')
    @Throttle({ default: { ttl: minutes(15), limit: 3 } })
    @HttpCode(HttpStatus.NO_CONTENT)
    @ApiOperation({ summary: 'Send a password reset link to the email' })
    @ApiNoContentResponse({
        description: 'Always returned, even if the email is not registered',
    })
    @ApiBadRequestResponse({ description: 'Validation failed' })
    @ApiTooManyRequestsResponse({ description: 'Too many reset requests' })
    async forgotPassword(@Body() dto: ForgotPasswordDto): Promise<void> {
        await this.passwordResetService.requestReset(dto.email);
    }

    @Post('reset-password')
    @HttpCode(HttpStatus.NO_CONTENT)
    @ApiOperation({
        summary: 'Set a new password using the token from the email',
    })
    @ApiNoContentResponse({
        description: 'Password changed, all sessions are logged out',
    })
    @ApiBadRequestResponse({
        description: 'Validation failed or the reset link is invalid or expired',
    })
    async resetPassword(@Body() dto: ResetPasswordDto): Promise<void> {
        await this.passwordResetService.resetPassword(dto.token, dto.password);
    }

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