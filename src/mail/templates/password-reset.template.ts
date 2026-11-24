import { MailMessage } from '../mail.service';

export function passwordResetEmail(params: {
  to: string;
  username: string;
  resetUrl: string;
  ttlMinutes: number;
}): MailMessage {
  const { to, username, resetUrl, ttlMinutes } = params;

  return {
    to,
    subject: 'Reset your Amari password',
    text: [
      `Hi ${username},`,
      '',
      'We received a request to reset your password.',
      `Open this link to set a new one (valid for ${ttlMinutes} minutes):`,
      resetUrl,
      '',
      "If you didn't request this, just ignore this email.",
    ].join('\n'),
    html: `
      <p>Hi ${username},</p>
      <p>We received a request to reset your password.</p>
      <p><a href="${resetUrl}">Set a new password</a></p>
      <p>The link is valid for ${ttlMinutes} minutes.</p>
      <p>If you didn't request this, just ignore this email.</p>
    `,
  };
}