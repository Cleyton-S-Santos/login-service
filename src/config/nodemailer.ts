import {createTransport} from "nodemailer"
import {config} from "dotenv"

config()
const nodemailerConfigs = {
    service: "gmail",
    host: "smtp.gmail.com",
    port: 465,
    secure: true,
    auth: {
        user: process.env.MAIL_USER,
        pass: process.env.MAIL_PASS
    },
    tls: {
        rejectUnauthorized: false,
    }
}

export const nodeMailerTransport = createTransport(nodemailerConfigs)