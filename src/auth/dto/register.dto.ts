import { Transform } from 'class-transformer';
import {
  IsEmail,
  IsString,
  IsStrongPassword,
  Length,
  Matches,
  MaxLength,
} from 'class-validator';
import { Match } from '../../common/validators/match.decorator';

const trim = ({ value }: { value: unknown }) =>
  typeof value === 'string' ? value.trim() : value;

export class RegisterDto {
  @Transform(trim)
  @IsString()
  @Length(3, 30)
  @Matches(/^[a-zA-Z0-9_.]+$/, {
    message: 'username can contain only latin letters, digits, "_" and "."',
  })
    /**
   * 3-30 chars: latin letters, digits, "_" and "."
   * @example jendos
   */
  username: string;

  @Transform(trim)
  @IsEmail()
  @MaxLength(254)
    /** @example jendos@mail.com */
  email: string;

  @IsString()
  @MaxLength(128)
  @IsStrongPassword(
    {
      minLength: 8,
      minLowercase: 1,
      minUppercase: 1,
      minNumbers: 1,
      minSymbols: 1,
    },
    {
      message:
        'password must be at least 8 characters and contain an uppercase letter, a lowercase letter, a digit and a special character',
    },
  )
    /**
   * Min 8 chars with an uppercase letter, a lowercase letter, a digit and a special character
   * @example Passw0rd!
   */
  password: string;

  @IsString()
  @Match('password', { message: 'passwords do not match' })
    /** @example Passw0rd! */
  confirmPassword: string;
}