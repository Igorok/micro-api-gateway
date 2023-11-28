import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { Injectable, UnauthorizedException } from '@nestjs/common';
import {
  WebRegistrationParamDto,
  WebLoginParamDto,
  WebUserDto,
} from 'micro-dto';
import { AuthRepo } from './auth.repo';
import { WebAccessTokens } from './auth.dto';

@Injectable()
export class AuthService {
  constructor(
    private configService: ConfigService,
    private jwtService: JwtService,
    private authRepo: AuthRepo,
  ) {}

  // method provides generation JWT tokens
  private async getTokens(user: WebUserDto): Promise<WebAccessTokens> {
    const { id, login, email, active, created_at } = user;
    const [accessToken, refreshToken] = await Promise.all([
      this.jwtService.signAsync(
        { id, login, email, active, created_at },
        {
          secret: this.configService.get<string>('JWT_SECRET'),
          expiresIn: this.configService.get<string>('JWT_EXPIRES'),
        },
      ),
      this.jwtService.signAsync(
        { id, login, email, active, created_at },
        {
          secret: this.configService.get<string>('JWT_REFRESH_SECRET'),
          expiresIn: this.configService.get<string>('JWT_REFRESH_EXPIRES'),
        },
      ),
    ]);

    return {
      accessToken,
      refreshToken,
    };
  }

  // method provides registration new user in the users service
  async registration(
    registrationDto: WebRegistrationParamDto,
  ): Promise<WebUserDto> {
    const { id, login, email, active, created_at } =
      await this.authRepo.registration(registrationDto);
    return { id, login, email, active, created_at };
  }

  // method provides a users login in the users service, and returns two JWT tokens
  async login(loginDto: WebLoginParamDto): Promise<WebAccessTokens> {
    const user = await this.authRepo.login(loginDto);

    const { id, login, email, active, created_at } = user;
    const { accessToken, refreshToken } = await this.getTokens({
      id,
      login,
      email,
      active,
      created_at,
    });

    return { accessToken, refreshToken };
  }

  // method requests a users data from users service, after success response returns updated tokens
  async refresh(user: WebUserDto): Promise<WebAccessTokens> {
    if (!user?.id) {
      throw new UnauthorizedException();
    }

    const activeUser = await this.authRepo.findUserById({
      id: user.id,
    });

    if (!activeUser) {
      throw new UnauthorizedException();
    }

    const { id, login, email, active, created_at } = activeUser;
    const { accessToken, refreshToken } = await this.getTokens({
      id,
      login,
      email,
      active,
      created_at,
    });

    return { accessToken, refreshToken };
  }
}
