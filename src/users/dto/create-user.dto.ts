import { ApiProperty } from "@nestjs/swagger";
import { IsString, IsNotEmpty, IsEmail, IsStrongPassword, MinLength, IsPhoneNumber, IsDateString } from "class-validator";

export class CreateUserDto {
    @ApiProperty({ example: 'first_name', description: 'Foydalanuvchi ismi'})
    @IsNotEmpty()
    @IsString()
    readonly first_name: string;

    @ApiProperty({ example: 'last_name', description: 'Foydalanuvchi familiyasi'})
    @IsNotEmpty()
    @IsString()
    readonly last_name: string;

    @ApiProperty({ example: 'userName', description: 'Foydalanuvchi niki'})
    @IsNotEmpty()
    @IsString()
    readonly username: string;

    @ApiProperty({ example: 'P@$$w00rd', description: 'Foydalanuvchi paroli'})
    @IsNotEmpty()
    @IsString()
    @MinLength(6)
    @IsStrongPassword()
    readonly password: string;

    @ApiProperty({ example: 'P@$$w00rd', description: 'Foydalanuvchi takroriy paroli'})
    @IsNotEmpty()
    @IsString()
    @MinLength(6)
    readonly confirm_password: string;

    @ApiProperty({ example: 'User@email.uz', description: 'Foydalanuvchi emaili'})
    @IsEmail()
    readonly email: string;

    @ApiProperty({ example: '912345678', description: 'Foydalanuvchi telefon raqami'})
    @IsNotEmpty()
    @IsPhoneNumber()
    readonly phone: string;

}
