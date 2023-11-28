import {
  Controller,
  Request,
  Post,
  UseGuards,
  UsePipes,
  Body,
  BadRequestException,
  HttpStatus,
} from '@nestjs/common';
import {
  ApiTags,
  ApiOperation,
  ApiResponse,
  ApiBearerAuth,
} from '@nestjs/swagger';
import { AuthService } from './auth.service';
import { JoiValidationPipe } from 'src/infrastructure/pipes/joi.validation.pipe';
import { registrationJoi, loginJoi } from './auth.joi';
import {
  WebLoginParamDto,
  WebUserDto,
  WebRegistrationParamDto,
} from 'micro-dto';
import { RefreshTokenGuard } from 'src/infrastructure/jwt/guard/jwt-refresh.guard';
import { WebAccessTokens } from './auth.dto';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Post('/registration')
  @ApiTags('Authorization')
  @ApiOperation({ summary: 'Registration of new user' })
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'Success',
    type: WebUserDto,
  })
  @UsePipes(new JoiValidationPipe(registrationJoi))
  async registration(
    @Body() body: WebRegistrationParamDto,
  ): Promise<WebUserDto> {
    try {
      return await this.authService.registration(body);
    } catch (error) {
      if (error?.code === 11000) {
        throw new BadRequestException('Duplicate user', {
          cause: error,
          description: 'User with same login or email already exists',
        });
      }

      throw new BadRequestException(error.message, {
        cause: error,
        description: error.message,
      });
    }
  }

  @Post('/login')
  @ApiTags('Authorization')
  @ApiOperation({ summary: 'Login in application' })
  @UsePipes(new JoiValidationPipe(loginJoi))
  async login(@Body() body: WebLoginParamDto): Promise<WebAccessTokens> {
    return this.authService.login(body);
  }

  @Post('/refresh')
  @UseGuards(RefreshTokenGuard)
  @ApiTags('Authorization')
  @ApiOperation({ summary: 'Refresh of JWT token' })
  @ApiBearerAuth('JWT')
  async refresh(@Request() req): Promise<WebAccessTokens> {
    return this.authService.refresh(req.user);
  }
}
