import nodemailer from "nodemailer";

export function probe() {
  const s = nodemailer.createTransport();
  return s.sendMail();
}
