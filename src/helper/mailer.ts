import {nodeMailerTransport} from "../config/nodemailer"
const baseURL = process.env.BASE_URL

export class MailerSend {
    async sendEmailBoasVindas(targetMail: string, username: string, endpointVerify: string){ 
      const mail = await nodeMailerTransport.sendMail({
        text: "Seja bem vindo!",
        subject: "Bem vindo ao event share, esperamos que seus eventos sejam epicos",
        from: "Time event-share <eventshareservices@gmail.com",
        html: `
        <div>
        <div>
            <h1>Boas vindas ${username}!!!</h1>
            <p>Por motivos de segurança, 
                precisamos que você acesse este <a href=${baseURL+endpointVerify+targetMail}>link</a>
            para podermos ter certeza que foi realmente você que fez o cadastro no nosso site
            </p>
        </div>
    </div>
        `,
        to: [targetMail]
      })
      console.log(mail)
    }

    async sendEmailChangePassword(targetMail: string, endpointVerify: string, senha: string){ 
        const mail = await nodeMailerTransport.sendMail({
            text: "Troca de senha!",
            subject: "Recebemos uma soliçitação de troca senha para essa conta, se não foi você apenas ignore e não clique em nada",
            from: "Time event-share <eventshareservices@gmail.com",
            html: `
            <div>
            <div>
                <h1>troca de senha!<h1>
                <p>Por motivos de segurança, 
                    precisamos que você acesse este <a href=${baseURL+endpointVerify+"?email="+targetMail+"&novasenha="+senha}>link</a>
                para podermos ter certeza que foi realmente você que fez essa requisição no nosso site
                </p>
            </div>
        </div>
            `,
            to: [targetMail]
          })
          console.log(mail)
      }
}