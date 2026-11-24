import {
  IsNotEmpty,
  IsString,
  IsStrongPassword,
  MaxLength,
} from 'class-validator';
import { Match } from '../../common/validators/match.decorator';
import {
  PASSWORD_MAX_LENGTH,
  STRONG_PASSWORD_MESSAGE,
  STRONG_PASSWORD_OPTIONS,
} from '../password-rules';

export class ResetPasswordDto {
  /** Token from the reset link (the part after `?token=`) */
  @IsString()
  @IsNotEmpty()
  @MaxLength(200)
  token: string;

  /** @example NewPassw0rd! */
  @IsString()
  @MaxLength(PASSWORD_MAX_LENGTH)
  @IsStrongPassword(STRONG_PASSWORD_OPTIONS, {
    message: STRONG_PASSWORD_MESSAGE,
  })
  password: string;

  /** @example NewPassw0rd! */
  @IsString()
  @Match('password', { message: 'passwords do not match' })
  confirmPassword: string;
}