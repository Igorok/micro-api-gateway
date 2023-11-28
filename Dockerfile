FROM node:18-alpine  As development

ENV APP_PORT=3000
ENV APP_ENV=DEV
ENV SOCKET_PORT=3001
ENV JWT_SECRET=jwt_secret_key
ENV JWT_EXPIRES=1m
ENV JWT_REFRESH_SECRET=jwt_refresh_secret_key
ENV JWT_REFRESH_EXPIRES=1d
ENV DOC_USER=usr
ENV DOC_PASS=pass
ENV API_USERS=http://localhost:3002
ENV API_MESSAGES=http://localhost:3003
ENV KAFKA_URI=localhost:9094
ENV KAFKA_RAW_MESSAGE_TOPIC=raw-message
ENV KAFKA_RAW_MESSAGE_GROUP=raw-messages
ENV KAFKA_READY_MESSAGE_TOPIC=ready-message
ENV KAFKA_READY_MESSAGE_GROUP=ready-messages
ENV KAFKA_ANALYSIS_MESSAGE_GROUP=ready-messages
ENV KAFKA_ANALYSIS_MESSAGE_GROUP=ready-messages

RUN mkdir -p /home/node/app/node_modules && chown -R node:node /home/node/app

WORKDIR /home/node/app

USER node

COPY package*.json ./

RUN npm ci

COPY --chown=node:node . .

EXPOSE 3000 3001

CMD [ "npm", "run", "start:dev" ]
