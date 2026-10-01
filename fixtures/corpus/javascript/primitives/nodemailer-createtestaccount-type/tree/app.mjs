import nodemailer from "nodemailer";

export function probe() {
  return nodemailer.createTestAccount();
}
