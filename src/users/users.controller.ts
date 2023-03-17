import { Controller, Get, Post, Body, Patch, Param, Res, HttpCode, HttpStatus } from '@nestjs/common';
import { UsersService } from './users.service';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { ApiOperation, ApiResponse, ApiTags } from '@nestjs/swagger';
import { Users } from './models/user.model';
import { Response } from 'express';
import { LoginUserDto } from './dto/login-user.dto';
import { CookieGetter } from '../decorators/cookieGetter.decorator';

@ApiTags('Users')
@Controller('users')
export class UsersController {
  constructor(private readonly usersService: UsersService) {}

  @ApiOperation({ summary: 'register User'})
  @ApiResponse({ status: 201, type: Users})
  @Post('signup')
  registration(
    @Body() createUserDto: CreateUserDto,
    @Res({ passthrough: true }) res: Response
  ){
    return this.usersService.registration(createUserDto, res);
  };

  @ApiOperation({ summary: 'login User'})
  @ApiResponse({ status: 200, type: Users})
  @HttpCode(HttpStatus.OK)
  @Post('signin')
  login(
    @Body() loginUserDto: LoginUserDto,
    @Res({ passthrough: true }) res: Response
  ){
    return this.usersService.login(loginUserDto, res);
  };
  
  @ApiOperation({summary: 'logout User'})
  @ApiResponse({status: 2000, type: Users})
  @HttpCode(HttpStatus.OK)
  @Post("signout")
  logout(
    @CookieGetter('refresh_token') refreshToken: string,
    @Res({passthrough:true}) res:Response
  ){
    console.log(refreshToken);
    
    return this.usersService.logout(refreshToken, res)
  };

  @ApiOperation({summary: 'activate user'})
  @ApiResponse({status: 200, type: [Users]})
  @Get('activate/:link')
  activate(@Param('link') link: string){
    return this.usersService.activate(link);
  };
}
