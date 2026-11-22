import type { Request } from 'express';
import { Role } from '../generated/prisma/client';

// The authenticated user attached to the request by JwtAuthGuard
export interface AuthUser {
  id: string;
  role: Role;
}

export interface RequestWithUser extends Request {
  user?: AuthUser;
}