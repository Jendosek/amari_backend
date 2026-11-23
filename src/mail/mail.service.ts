import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { createTransport, getTestMessageUrl, Transporter } from 'nodemailer';

export interface MailMessage {
  to: string;
  subject: string;
  text: string;
  html: string;
}

@Injectable()
export class MailService {
  private readonly logger = new Logger(MailService.name);
  private readonly transporter: Transporter;
  private readonly from: string;

  constructor(config: ConfigService) {
    const port = config.getOrThrow<number>('SMTP_PORT');

    this.transporter = createTransport({
      host: config.getOrThrow<string>('SMTP_HOST'),
      port,
      secure: port === 465,
      auth: {
        user: config.getOrThrow<string>('SMTP_USER'),
        pass: config.getOrThrow<string>('SMTP_PASS'),
      },
    });
    this.from = config.getOrThrow<string>('MAIL_FROM');
  }

  async send(message: MailMessage): Promise<void> {
    const info = await this.transporter.sendMail({
      from: this.from,
      ...message,
    });

    const previewUrl = getTestMessageUrl(info);
    if (previewUrl) {
      this.logger.log(`Email preview: ${previewUrl}`);
    }
  }
}