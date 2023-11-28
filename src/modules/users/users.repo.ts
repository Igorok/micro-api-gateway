import { HttpService } from '@nestjs/axios';
import {
  BadRequestException,
  Injectable,
  InternalServerErrorException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import {
  FindAllDto,
  FindByIdDto,
  WebUserDto,
  WebUsersAllDto,
} from 'micro-dto';

@Injectable()
export class UsersRepo {
  constructor(
    private configService: ConfigService,
    private readonly httpService: HttpService,
  ) {}

  errorMessage: string = 'Oops something went wrong';

  // provides communication with user service through http requests
  async usersRequest(method: string, url: string, param?: any) {
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

  // provides receiving users list data from the users service
  async findAll(param: FindAllDto): Promise<WebUsersAllDto> {
    const searchParam = new URLSearchParams(
      Object.entries(param).map((p) => p),
    );
    let url = `/users/find-all?${searchParam.toString()}`;
    return await this.usersRequest('get', url);
  }

  // provides receiving user detail data from the users service
  async findUserById(param: FindByIdDto): Promise<WebUserDto> {
    return await this.usersRequest('get', `/users/find-one/${param.id}`);
  }
}
