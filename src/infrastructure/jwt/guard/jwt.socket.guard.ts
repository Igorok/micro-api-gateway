import * as jwt from 'jsonwebtoken';
import { ConfigService } from '@nestjs/config';
import { WsException } from '@nestjs/websockets';
import { CanActivate, ExecutionContext, Injectable } from '@nestjs/common';

@Injectable()
export class JwtSocketGuard implements CanActivate {
  constructor(private configService: ConfigService) {}

  canActivate(context: ExecutionContext) {
    try {
      const client = context.switchToWs().getClient();
      const data = context.switchToWs().getData();
      const user: any = jwt.verify(
        data.token || '',
        this.configService.get<string>('JWT_SECRET'),
      );
      client.handshake.user = user;
      return true;
    } catch (error) {
      throw new WsException(error.message);
    }
  }
}
