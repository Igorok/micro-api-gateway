import { Injectable } from '@nestjs/common';
import {
  FindAllDto,
  FindByIdDto,
  WebUserDto,
  WebUsersAllDto,
} from 'micro-dto';
import { UsersRepo } from './users.repo';

@Injectable()
export class UsersService {
  constructor(private usersRepo: UsersRepo) {}

  // provides the list of users
  async findAll(param: FindAllDto, user: WebUserDto): Promise<WebUsersAllDto> {
    param.excludeIds = [user.id];
    return this.usersRepo.findAll(param);
  }

  // provides detail information about user
  async findUserById(param: FindByIdDto): Promise<WebUserDto> {
    const { id, login, email, active, created_at } =
      await this.usersRepo.findUserById(param);
    return { id, login, email, active, created_at };
  }
}
