import { IsJWT, MaxLength } from 'class-validator';

export class GoogleLoginDto {
  /** ID token (credential) received from Google Identity Services on the frontend */
  @IsJWT()
  @MaxLength(4096)
  idToken: string;
}