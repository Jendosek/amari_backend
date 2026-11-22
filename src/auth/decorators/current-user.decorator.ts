import {
  createParamDecorator,
  ExecutionContext,
  UnauthorizedException,
} from '@nestjs/common';
import { AuthUser, RequestWithUser } from '../auth-user';

// Injects the authenticated user into a controller method: @CurrentUser() user
export const CurrentUser = createParamDecorator(
  (_data: unknown, ctx: ExecutionContext): AuthUser => {
    const request = ctx.switchToHttp().getRequest<RequestWithUser>();
    if (!request.user) {
      // Only happens if the decorator is used on a @Public() route
      throw new UnauthorizedException();
    }
    return request.user;
  },
);