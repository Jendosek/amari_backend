import { Role, User } from '../../generated/prisma/client';

export class UserResponseDto {
  id: string;
  username: string;
  email: string;
  role: Role;
  createdAt: Date;

  static fromEntity(user: User): UserResponseDto {
    return {
      id: user.id,
      username: user.username,
      email: user.email,
      role: user.role,
      createdAt: user.createdAt,
    };
  }
}