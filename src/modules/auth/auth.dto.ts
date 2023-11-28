import { ApiProperty } from '@nestjs/swagger';

export class WebAccessTokens {
  @ApiProperty({ description: 'JWT access', nullable: false })
  accessToken: string;

  @ApiProperty({ description: 'JWT refresh', nullable: false })
  refreshToken: string;
}
