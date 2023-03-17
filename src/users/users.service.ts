import { Injectable, BadRequestException, UnauthorizedException, ForbiddenException, HttpException, HttpStatus } from '@nestjs/common';
import { CreateUserDto } from './dto/create-user.dto';
import * as bcrypt from 'bcrypt';
import { UpdateUserDto } from './dto/update-user.dto';
import { InjectModel } from '@nestjs/sequelize';
import { Users } from './models/user.model';
import { JwtService } from '@nestjs/jwt';
import { v4 as uuidv4, v4 } from 'uuid';
import { Response } from 'express';
import { LoginUserDto } from './dto/login-user.dto';
import { access } from 'fs';
import { MailService } from '../mail/mail.service';

@Injectable()
export class UsersService {
  constructor(
    @InjectModel(Users) private readonly userRepo: typeof Users,
    private readonly jwtService: JwtService,
    private readonly mailService: MailService
  ) {};

  async registration(createUserDto: CreateUserDto, res: Response) {
    const user = await this.userRepo.findOne({
      where: { username: createUserDto.username },
    });
    if (user) {
      throw new BadRequestException('Username already exists!');
    };
    if (createUserDto.password !== createUserDto.confirm_password) {
      throw new BadRequestException('Password is not match!');
    };

    const hashed_password = await bcrypt.hash(createUserDto.password, 7);
    const newUser = await this.userRepo.create({
      ...createUserDto,
      hashed_password: hashed_password,
    });
    const tokens = await this.getTokens(newUser);
    const hashed_refresh_token = await bcrypt.hash(tokens.refresh_token, 7);
    const uniqueKey: string = uuidv4();
    const updatedUser = await this.userRepo.update(
      {
        hashed_refresh_token: hashed_refresh_token,
        activation_link: uniqueKey,
      },
      {
        where: { id: newUser.id },
        returning: true,
      }
    );
    res.cookie('refresh_token', tokens.refresh_token, {
      maxAge: 15 * 24 * 60 * 60 * 1000,
      httpOnly: true
    });

    await this.mailService.sendUserConfirmation(updatedUser[1][0]);

    const response = {
      message: 'User registred',
      user: updatedUser[1][0],
      tokens,
    };
    return response;
  };

  async getTokens(user: Users) {
    const jwtPayload = {
      id: user.id,
      is_active: user.is_active,
      is_owner: user.is_owner,
    };
    const [accessToken, refreshToken] = await Promise.all([
      this.jwtService.signAsync(jwtPayload, {
        secret: process.env.ACCESS_TOKEN_KEY,
        expiresIn: process.env.ACCESS_TOKEN_TIME,
      }),
      this.jwtService.signAsync(jwtPayload, {
        secret: process.env.REFRESH_TOKEN_KEY,
        expiresIn: process.env.REFRESH_TOKEN_TIME,
      }),
    ]);
    return {
      access_token: accessToken,
      refresh_token: refreshToken,
    };
  };

  async login(loginUserDto: LoginUserDto, res: Response){
    const { email, password } = loginUserDto;
    const user = await this.userRepo.findOne({ where: { email } });
    if(!user){
      throw new UnauthorizedException('User not registred');
    };
    const isMatchPass = await bcrypt.compare(password, user.hashed_password);
    if(!isMatchPass){
      throw new UnauthorizedException('User not registred(pass)');
    }
    const tokens = await this.getTokens(user);
    const hashed_refresh_token = await bcrypt.hash(tokens.refresh_token, 7);
    const updatedUser = await this.userRepo.update(
      {hashed_refresh_token: hashed_refresh_token},
        {where: {id: user.id}, returning: true }
    );
    res.cookie('refresh_token', tokens.refresh_token, {
      maxAge: 15 * 24 * 60 * 60 * 1000,
      httpOnly: true
    });
    const response = {
      message: 'User logged in',
      user: updatedUser[1][0],
      tokens,
    };
    return response;
  };

  async logout(refreshToken: string, res: Response){
    const userData  = await this.jwtService.verify(refreshToken,{
      secret: process.env.REFRESH_TOKEN_KEY
    });
    if(!userData){
      throw new ForbiddenException('User not found');
    };
    const updatedUser = await this.userRepo.update(
      {hashed_refresh_token: null},
      {where: {id: userData.id}, returning: true}
    );
    res.clearCookie('refresh_token');
    const response = {
      message: 'User logged out successfully',
      user: updatedUser[1][0]
    };
    return response;
  };

  async activate(link: string){
    if(!link){
      throw new BadRequestException('Activation link not found');
    }
    const updatedUser = await this.userRepo.update(
      {is_active: true},
      {where: {activation_link: link, is_active: false}, returning: true}
    );
    if(!updatedUser[1][0]){
      throw new BadRequestException('User already activated');
    }
        
    const response = {
      message: 'user activated  successfully',
      user: updatedUser
    };
    return response;
  };

  
}
