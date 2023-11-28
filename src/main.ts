import * as basicAuth from 'express-basic-auth';
import { NestFactory } from '@nestjs/core';
import { ConfigService } from '@nestjs/config';
import { SwaggerModule, DocumentBuilder } from '@nestjs/swagger';
import { AppModule } from 'src/app.module';
import { SocketIoAdapter } from 'src/modules/messages/io.adapter';

async function bootstrap() {
  const app = await NestFactory.create(AppModule, {
    cors: true,
  });
  const configService: ConfigService = app.get(ConfigService);

  app.useWebSocketAdapter(new SocketIoAdapter(app, configService));

  app.use(
    ['/swagger'],
    basicAuth({
      challenge: true,
      users: {
        [configService.get<string>('DOC_USER')]:
          configService.get<string>('DOC_PASS'),
      },
    }),
  );

  const swaggerConfig = new DocumentBuilder()
    .setTitle('Api Gateway')
    .setVersion('0.0.1')
    .addBearerAuth(
      { type: 'http', scheme: 'bearer', bearerFormat: 'JWT' },
      'JWT',
    )
    .build();

  const document = SwaggerModule.createDocument(app, swaggerConfig);

  SwaggerModule.setup('swagger', app, document, {
    swaggerOptions: {
      persistAuthorization: true,
    },
  });

  await app.listen(configService.get<string>('APP_PORT'));
}
bootstrap();
