import { Module } from '@nestjs/common';
import { LoginService } from './login.service';
import { LoginController } from './login.controller';
import { PrismaService } from 'src/database/prismaService';
import { MailerSend } from 'src/helper/mailer';
import { HttpModule } from '@nestjs/axios';

@Module({
  imports: [HttpModule],
  controllers: [LoginController],
  providers: [LoginService, PrismaService, MailerSend]
})
export class LoginModule {}
