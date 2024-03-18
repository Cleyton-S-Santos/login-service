import { HttpException, HttpStatus, Injectable, Logger, NotFoundException } from '@nestjs/common';
import { PrismaService } from 'src/database/prismaService';
import { CreateLoginDto } from './dto/create-login.dto';
import { UpdateLoginDto } from './dto/update-login.dto';
import {hash, compare} from "bcrypt";
import { MailerSend } from 'src/helper/mailer';
import {sign} from "jsonwebtoken";
import { ConfigService } from '@nestjs/config';
import { HttpService } from '@nestjs/axios';
import { KeyCloackTokenModel } from 'src/helper/KeyClockTokenModel';
import * as queryString from 'querystring';
import axios from 'axios';

@Injectable()
export class LoginService {

  private keycloakLoginUri: string;
  private keycloakResponseType: string;
  private keycloakScope: string;
  private keycloakRedirectUri: string;
  private keycloakClientId: string;
  private keycloakClientSecret: string;
  private keycloakTokenUri: string;
  private keycloakLogoutUri: string;

  constructor(private prismaService: PrismaService, private mailSend: MailerSend, readonly _config: ConfigService, readonly _http: HttpService){
    this.keycloakLoginUri = _config.get('KEYCLOAK_LOGIN_URI');
    this.keycloakResponseType = _config.get('KEYCLOAK_RESPONSE_TYPE');
    this.keycloakScope = _config.get('KEYCLOAK_SCOPE');
    this.keycloakRedirectUri = _config.get('KEYCLOAK_REDIRECT_URI');
    this.keycloakClientId = _config.get('KEYCLOAK_CLIENT_ID'); 
    this.keycloakClientSecret = _config.get('KEYCLOAK_CLIENT_SECRET');
    this.keycloakTokenUri = this._config.get('KEYCLOAK_TOKEN_URI');
    this.keycloakLogoutUri = this._config.get('KEYCLOAK_LOGOUT_URI');
  }

  async create(createLoginDto: CreateLoginDto) { 
    createLoginDto.emailValidation = false
    createLoginDto.password = await hash(createLoginDto.password, 10)
    try{
      // await this.mailSend.sendEmailBoasVindas(createLoginDto.email, createLoginDto.username, "/login/verify/");
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

  getUrlLogin(): any {
    return { url: `${this.keycloakLoginUri}`
    +`?client_id=${this.keycloakClientId}`
        +`&response_type=${this.keycloakResponseType}`
        +`&scope=${this.keycloakScope}`
        +`&redirect_uri=${this.keycloakRedirectUri}`
    }
  }

  getToken(code: string){
    const params = {
      grant_type: "authorization_code",
      client_id: this.keycloakClientId,
      client_secret: this.keycloakClientSecret,
      code: code,
      redirect_uri: this.keycloakRedirectUri
    }

    return this.makePostRequestToGetToken(this.keycloakTokenUri, queryString.stringify(params), this.getContentType());
  }

  async makePostRequestToGetToken(url, queryParams, headers) {
    try {
      const response: any = await axios.post(url, queryParams, { headers });
      return new KeyCloackTokenModel (
        response.data.access_token,
        response.data.refresh_token,
        response.data.expires_in,
        response.data.refresh_expires_in
    );
    } catch (error) {
      throw new Error(`Error making POST request: ${error}`);
    }
  }
  
  getContentType() {
    return { headers: { 'Content-Type' : 'application/x-www-form-urlencoded'} }
  }
}
