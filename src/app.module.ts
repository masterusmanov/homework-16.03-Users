import { Module } from '@nestjs/common';
import { UsersModule } from './users/users.module';
import { ConfigModule } from "@nestjs/config";
import { ServeStaticModule } from '@nestjs/serve-static';
import { SequelizeModule } from '@nestjs/sequelize';
import { resolve } from "path";



@Module({
  imports: [
    ConfigModule.forRoot({envFilePath: '.env', isGlobal: true}),
        ServeStaticModule.forRoot({
            rootPath: resolve(__dirname, 'static')
        }),
        SequelizeModule.forRoot({
            dialect: 'postgres',
            host: process.env.POSTGRES_HOST,
            port: Number(process.env.POSTGRES_PORT),
            username: process.env.POSTGRES_USER,
            password: String(process.env.POSTGRES_PASSWORD),
            database: process.env.POSTGRES_DB,
            models: [],
            autoLoadModels: true,
            logging: false
        }),
    UsersModule
  ],
  controllers: [],
  providers: [],
})
export class AppModule {}
