import nodemailer from "nodemailer";

export function probe(target) {
  return nodemailer.createTransport(target);
}
