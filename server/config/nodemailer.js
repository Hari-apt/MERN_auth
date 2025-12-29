import nodemailer from "nodemailer"

const transporter = nodemailer.createTransport({

    host: 'smtp.gmail.com',
    port: 587,
    secure: false,
    auth:{
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS, 
    },
  connectionTimeout: 10000, // 10s
  greetingTimeout: 10000,
  socketTimeout: 10000
});


export default transporter



import { Resend } from "resend";

export const resend = new Resend(process.env.RESEND_API_KEY);