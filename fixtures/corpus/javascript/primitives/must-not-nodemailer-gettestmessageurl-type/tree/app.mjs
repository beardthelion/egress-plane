import m from "nodemailer";

export function probe() {
  return [
    m.getTestMessageUrl,
  ];
}
