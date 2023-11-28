import { Injectable } from '@nestjs/common';
import {
  FindByIdsDto,
  PrivateRoomQueryDto,
  RoomDataDto,
  WebUsersAllDto,
} from 'micro-dto';
import { MessagesRepo } from './message.repo';

@Injectable()
export class MessagesService {
  constructor(private messagesRepo: MessagesRepo) {}

  async getPrivateRoom(param: PrivateRoomQueryDto): Promise<RoomDataDto> {
    return this.messagesRepo.getPrivateRoom(param);
  }
  async getUsersByIds(param: FindByIdsDto): Promise<WebUsersAllDto> {
    return this.messagesRepo.getUsersByIds(param);
  }
}
