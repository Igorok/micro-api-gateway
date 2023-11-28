import { HttpService } from '@nestjs/axios';
import {
  BadRequestException,
  Injectable,
  InternalServerErrorException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import {
  FindByIdDto,
  WebLoginParamDto,
  WebRegistrationParamDto,
  WebUserDto,
} from 'micro-dto';

@Injectable()
export class AuthRepo {
  constructor(
    private configService: ConfigService,
    private readonly httpService: HttpService,
  ) {}

  errorMessage: string = 'Oops something went wrong';

  // method provides communication with user service through http requests
  private async usersRequest(method: string, url: string, param?: any) {
    try {
      const uri = `${this.configService.get<string>('API_USERS')}${url}`;
      const response = await this.httpService.axiosRef?.[method](uri, param);
      return response.data;
    } catch (error) {
      if (error.response?.data?.statusCode === 400) {
        throw new BadRequestException(error.response.data.message);
      }
      throw new InternalServerErrorException(
        error.response?.data?.message || this.errorMessage,
      );
    }
  }

  // method provides login in the users service and receiving data about user
  async login(param: WebLoginParamDto): Promise<WebUserDto> {
    return await this.usersRequest('post', '/users/login', param);
  }

  // method provides creation new users in the user service and receiving data about user
  async registration(param: WebRegistrationParamDto): Promise<WebUserDto> {
    return await this.usersRequest('post', '/users/registration', param);
  }

  // method provides receiving data about user
  async findUserById(param: FindByIdDto): Promise<WebUserDto> {
    return await this.usersRequest('get', `/users/find-one/${param.id}`);
  }
}
