import type { IsStrongPasswordOptions } from 'class-validator';

// Shared by registration and password reset, so the rules can't drift apart
export const PASSWORD_MAX_LENGTH = 128;

export const STRONG_PASSWORD_OPTIONS: IsStrongPasswordOptions = {
  minLength: 8,
  minLowercase: 1,
  minUppercase: 1,
  minNumbers: 1,
  minSymbols: 1,
};

export const STRONG_PASSWORD_MESSAGE =
  'password must be at least 8 characters and contain an uppercase letter, a lowercase letter, a digit and a special character';