import nodemailer from "nodemailer";

const transport = nodemailer.createTransport({
  host: "sandbox.smtp.mailtrap.io",
  port: 2525,
  auth: {
    user: process.env.MAILTRAP_USER,
    pass: process.env.MAILTRAP_PASSWORD,
  },
});
const sendEmailVerification = async (email: string, link: string) => {
  await transport.sendMail({
    from: "verification@myapp.com",
    to: email,
    html: `<h1>Please click on <a href="${link}">this link</a> to verify your account.</h1>`,
  });
};

const mail = {
  sendEmailVerification,
};

export default mail;
