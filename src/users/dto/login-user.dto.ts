import { ApiProperty } from "@nestjs/swagger";
import { IsNotEmpty, IsString, IsEmail } from "class-validator";



export class LoginUserDto{
    @ApiProperty({
        example: 'email@mail.uz',
        description: 'Foydalanuvchi elektron pochtasi'
    })
    @IsEmail()
    email: string;

    @ApiProperty({
        example: 'P@$$ww00rd',
        description: 'Foydalanuvchi paroli'
    })
    @IsNotEmpty()
    @IsString()
    password: string;


}