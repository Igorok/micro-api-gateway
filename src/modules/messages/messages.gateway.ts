import { Kafka, Producer, Consumer, KafkaMessage } from 'kafkajs';
import { ConfigService } from '@nestjs/config';
import {
  UseGuards,
  Logger,
  OnModuleInit,
  OnModuleDestroy,
} from '@nestjs/common';
import {
  WebSocketGateway,
  WebSocketServer,
  SubscribeMessage,
  ConnectedSocket,
  MessageBody,
} from '@nestjs/websockets';
import { JwtSocketGuard } from 'src/infrastructure/jwt/guard/jwt.socket.guard';
import { MessagesService } from './message.service';
import { MessageWebDto } from 'micro-dto';

@WebSocketGateway()
export class MessagesGateway implements OnModuleInit, OnModuleDestroy {
  constructor(
    private messagesService: MessagesService,
    private configService: ConfigService,
  ) {}

  private readonly logger = new Logger(MessagesGateway.name);

  // initialization of the kafka library
  private readonly kafka: Kafka = new Kafka({
    clientId: 'api-gateway',
    brokers: [this.configService.get<string>('KAFKA_URI')],
  });
  // producer - producing messages in a topic
  private readonly producer: Producer = this.kafka.producer();
  // consumer - consuming messages from a topic
  private readonly consumer: Consumer = this.kafka.consumer({
    groupId: this.configService.get<string>('KAFKA_READY_MESSAGE_GROUP'),
  });

  // web socket
  @WebSocketServer() server;

  // connection to the kafka message broker at the moment of initialization
  async onModuleInit() {
    try {
      // connection
      await this.producer.connect();

      // consumer
      await this.consumer.connect();
      await this.consumer.subscribe({
        topic: this.configService.get<string>('KAFKA_READY_MESSAGE_TOPIC'),
        fromBeginning: true,
      });
      await this.consumer.run({
        eachMessage: async ({ topic, partition, message }) => {
          this.receiveReadyMessage(message);
        },
      });
    } catch (error) {
      this.logger.error(error);
    }
  }

  // disconnection from the kafka message broker at the moment of destruction
  async onModuleDestroy() {
    try {
      await this.producer.disconnect();
      await this.consumer.disconnect();
    } catch (error) {
      this.logger.error(error);
    }
  }

  // method emits the socket.io event after receiving a new message from the kafka
  receiveReadyMessage(kafkaMessage: KafkaMessage) {
    try {
      const messageValue: MessageWebDto = JSON.parse(
        kafkaMessage.value.toString(),
      );
      this.server.to(messageValue.room_id).emit('message', messageValue);
    } catch (error) {
      this.logger.error(error);
    }
  }

  // listening of the socket.io messages and producing to the kafka
  @UseGuards(JwtSocketGuard)
  @SubscribeMessage('message')
  async onMessage(@ConnectedSocket() client: any, @MessageBody() data: any) {
    try {
      const { uuid, message, room_id } = data;
      const { id: userId } = client.handshake.user;
      const rawMessage: MessageWebDto = {
        uuid,
        message,
        room_id,
        user_id: userId,
        created_at: new Date(),
      };

      await this.producer.send({
        topic: this.configService.get<string>('KAFKA_RAW_MESSAGE_TOPIC'),
        messages: [
          {
            key: room_id,
            value: JSON.stringify(rawMessage),
          },
        ],
      });
    } catch (error) {
      this.logger.error(error);
    }
  }

  // listening of the join to chat room from the socket.io and emits room information to the front-end service
  @UseGuards(JwtSocketGuard)
  @SubscribeMessage('joinPrivateRoom')
  async joinPrivateRoom(
    @ConnectedSocket() client: any,
    @MessageBody() data: any,
  ) {
    try {
      const { userId: secondId } = data;
      const { id: currentId } = client.handshake.user;
      const roomData = await this.messagesService.getPrivateRoom({
        userIds: [secondId, currentId],
      });
      const roomUsers = await this.messagesService.getUsersByIds({
        ids: [secondId, currentId],
      });
      const roomId = roomData?.room?.id;

      client.join(roomId);
      client.emit('joinPrivateRoom', {
        users: roomUsers?.users,
        room: roomData?.room,
        messages: roomData?.messages,
      });
      client.to(roomId).emit('joinPrivateRoom', {
        users: roomUsers?.users,
        room: roomData?.room,
        messages: roomData?.messages,
      });
    } catch (error) {
      this.logger.error(error);
    }
  }
}
