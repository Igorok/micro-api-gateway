import { Module } from '@nestjs/common';
import { MessagesGateway } from './messages.gateway';
import { MessagesService } from './message.service';
import { MessagesRepo } from './message.repo';
import { HttpModule } from '@nestjs/axios';

@Module({
  imports: [HttpModule],
  providers: [MessagesGateway, MessagesService, MessagesRepo],
})
export class MessagesModule {}
