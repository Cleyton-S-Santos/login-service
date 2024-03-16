import { HttpException, HttpStatus, Injectable, Logger, NotFoundException } from '@nestjs/common';
import { PrismaService } from 'src/database/prismaService';
import { CreateLoginDto } from './dto/create-login.dto';
import { UpdateLoginDto } from './dto/update-login.dto';
import {hash, compare} from "bcrypt";
import { MailerSend } from 'src/helper/mailer';
import {sign} from "jsonwebtoken";

@Injectable()
export class LoginService {
  constructor(private prismaService: PrismaService, private mailSend: MailerSend){}

  async create(createLoginDto: CreateLoginDto) { 
    createLoginDto.emailValidation = false
    createLoginDto.password = await hash(createLoginDto.password, 10)
    try{
      await this.mailSend.sendEmailBoasVindas
      (createLoginDto.email, createLoginDto.username, "/login/verify/");
      Logger.log("Usuario criado LoginService.create")
      return await this.prismaService.usuario.create({data:createLoginDto})
    } catch(e){
      Logger.error("Erro ao criar usuario LoginService.create", e)
      return e
    }
  }

  async findAll() {
    Logger.log("LoginService.findAll")
    return this.prismaService.usuario.findMany();
  }

  async findOne(email: string) {
    try{
      Logger.log("Try LoginService.findOne")
      return this.prismaService.usuario.findUnique({
        where:{
          email: email
        }
      })
    } catch(e){
      Logger.error("Erro LoginService.findOne", e)
      return e
    };
  }

  async update(id: string, updateLoginDto: UpdateLoginDto) {
    try{
      Logger.log("Entrada LoginService.update", updateLoginDto.username)
      return await this.prismaService.usuario.update({
        data: updateLoginDto,
          where: {
            id: id
          }
      })
    } catch(e){
      Logger.error("Erro LoginSercie.update", e)
    }
  }

  async remove(id: string) {
    try{
      Logger.log("Entrada LoginService.remove")
      return this.prismaService.usuario.delete({
        where: {
          id: id
        }
      })
    } catch(e){
      Logger.error(e)
    }
  }

  async verifyAccount(email: string){
    try{
      await this.prismaService.usuario.update({
        data: {emailValidation: true},
          where: {
            email
          }
      })

      return "<h1>Validado, obrigado!</h1>"
    }catch(e){
      Logger.error("Erro LoginService.verifyAccount", e)
      return e;
    }
  }

  async mailChangePass(email: string, novasenha: string){
    const senha = await hash(novasenha, 15)
    try{
      const emailExists = this.prismaService.usuario.findUnique({
        where: {
          email: email
        }
      })

      if(!emailExists){
        Logger.error("LoginService.mailChangePass Email não foi encontrado na base de dados")
        throw new NotFoundException("Email não encontrado")
      }
      Logger.log("Entrada LoginService.mailChangePass")
      await this.mailSend.sendEmailChangePassword(email, "/login/password-change/confirm/", senha)
    } catch(e){
      Logger.error("Erro LoginService.mailChangePass", e)
      return e
    }
  }

  async changePass(email: string, novasenha: string){
    try{
      Logger.log("Entrada LoginService.changePass")
      await this.prismaService.usuario.update({
        data: {password: novasenha},
          where: {
            email: email
          }
      })
      return "<h1>Sua senha foi alterada com sucesso</h1>"
    } catch(e){
      Logger.error("Entrada LoginService.changePass", e)
      return e
    }
  }

  async loginUser(email: string, senha: string){
    Logger.log("Entrada loginService.loginUser")    
    const usuario = await this.prismaService.usuario.findFirst({
      where: {
        email: email
      }
    })

    if(!usuario){
      Logger.error("loginService.loginUser Usuario não encontrado")
      throw new HttpException("Usuario não encontrado", HttpStatus.NOT_FOUND)
    }

    const isSamePass = await compare(senha, usuario.password);

    if(isSamePass){
      Logger.log("Usuario logado, retorno de token")
      return{
        token: sign(usuario, process.env.JWT_SECRET, {expiresIn: "12h"}),
        usuario: usuario.id
      }
    } else {
      Logger.error("loginService.loginUser Login/senha invalidos")
      throw new HttpException("Login/senha invalidos", HttpStatus.BAD_REQUEST)
    }
  }
}
