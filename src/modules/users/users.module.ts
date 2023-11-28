import { Module } from '@nestjs/common';
import { HttpModule } from '@nestjs/axios';
import { UsersService } from 'src/modules/users/users.service';
import { UsersController } from 'src/modules/users/users.controller';
import { UsersRepo } from './users.repo';

@Module({
  imports: [HttpModule],
  providers: [UsersService, UsersRepo],
  controllers: [UsersController],
})
export class UsersModule {}
