import { ApiProperty } from '@nestjs/swagger';
import { UserResponseDto } from '../../users/dto/user-response.dto';

export class AuthResponseDto {
  @ApiProperty({
    description: 'Short-lived JWT, send it as `Authorization: Bearer <token>`',
  })
  accessToken: string;

  @ApiProperty({ type: () => UserResponseDto })
  user: UserResponseDto;
}