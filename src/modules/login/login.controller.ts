import { Controller, Get, Post, Body, Patch, Param, Delete, Logger, Query } from '@nestjs/common';
import { LoginService } from './login.service';
import { CreateLoginDto } from './dto/create-login.dto';
import { UpdateLoginDto } from './dto/update-login.dto';
import { LoginDTO } from './dto/login.dto';

@Controller('login')
export class LoginController {
  constructor(private readonly loginService: LoginService) {}

  @Post()
  create(@Body() createLoginDto: CreateLoginDto) {
    Logger.log("Entrada LoginController.create")
    return this.loginService.create(createLoginDto);
  }

  @Get()
  findAll() {
    Logger.log("Entrada LoginController.findAll")
    return this.loginService.findAll();
  }

  @Get(':id')
  findOne(@Param('id') id: string) {
    Logger.log("Entrada LoginController.findOne")
    return this.loginService.findOne(id);
  }

  @Patch(':id')
  update(@Param('id') id: string, @Body() updateLoginDto: UpdateLoginDto) {
    Logger.log('Entrada LoginController.update')
    return this.loginService.update(id, updateLoginDto);
  }

  @Delete(':id')
  remove(@Param('id') id: string) {
    Logger.log("Entrada LoginController.remove")
    return this.loginService.remove(id);
  }

  @Get("/verify/:email")
  verifyAcc(@Param("email") email:string){
    Logger.log("Verify account started")
    return this.loginService.verifyAccount(email)
  }

  @Get("/password-change/:email/:novasenha")
  changePassword(@Param("email") email:string, @Param("novasenha") senha: string){
    Logger.log("Entrada LoginController.changePassword solicitação de troca")
    return this.loginService.mailChangePass(email, senha)
  }

  @Get("/password-change/confirm")
  confirmChange(@Query("email") email:string, @Query("novasenha") senha: string){
    Logger.log("Entrada LoginController.confirmChange confirmação de troca de senha")
    return this.loginService.changePass(email, senha)
  }

  @Post("/user")
  logUser(@Body() data: LoginDTO){
   Logger.log("Entrada LoginController.logUser: " + data.email)
    return this.loginService.loginUser(data.email, data.senha)
  }
}
