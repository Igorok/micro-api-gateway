import {
  ApiBearerAuth,
  ApiOperation,
  ApiResponse,
  ApiTags,
} from '@nestjs/swagger';
import {
  Controller,
  Get,
  HttpStatus,
  Param,
  Query,
  UseGuards,
  UsePipes,
  Request,
} from '@nestjs/common';
import { JoiValidationPipe } from 'src/infrastructure/pipes/joi.validation.pipe';
import {
  FindAllDto,
  FindByIdDto,
  WebUserDto,
  WebUsersAllDto,
} from 'micro-dto';
import { findByIdJoi, findAllJoi } from './users.joi';
import { UsersService } from './users.service';
import { JwtAuthGuard } from 'src/infrastructure/jwt/guard/jwt-auth.guard';

@Controller('users')
export class UsersController {
  constructor(private usersService: UsersService) {}

  @Get('/find-all')
  @ApiTags('Users')
  @ApiOperation({ summary: 'List of users' })
  @ApiBearerAuth('JWT')
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'Success',
    type: WebUsersAllDto,
  })
  @UseGuards(JwtAuthGuard)
  @UsePipes(new JoiValidationPipe(findAllJoi))
  findAll(
    @Query() params: FindAllDto,
    @Request() req,
  ): Promise<WebUsersAllDto> {
    return this.usersService.findAll(params, req.user);
  }

  @Get('/find-one/:id')
  @UseGuards(JwtAuthGuard)
  @UsePipes(new JoiValidationPipe(findByIdJoi))
  @ApiTags('Users')
  @ApiOperation({ summary: 'Get user by id' })
  @ApiBearerAuth('JWT')
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'Success',
    type: WebUserDto,
  })
  findOne(@Param() params: FindByIdDto): Promise<WebUserDto> {
    return this.usersService.findUserById(params);
  }
}
