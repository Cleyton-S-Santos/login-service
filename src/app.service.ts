import { Injectable } from '@nestjs/common';
import {config} from "dotenv"

config()
@Injectable()
export class AppService {
  getHello(): string {
    return "Service up: " + process.env.VERSION;
  }
}
