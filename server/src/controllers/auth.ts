import { RequestHandler } from "express";
import UserModal from "src/modals/user";
import crypto from "crypto";
import nodemailer from "nodemailer";

import AuthVerficationTokenModal from "src/modals/authVerficationToken";
import { sendErrorRes } from "src/utils/helper";
import jwt from "jsonwebtoken";

export const createNewUser: RequestHandler = async (req, res, next) => {
  const { name, email, password } = req.body;

  // Validate incoming data is ok or not send error if not ok
  if (!name || !email || !password) {
    return sendErrorRes(res, "Please provide all fields", 442);
  }

  // Check if user already exists in database
  const existingUser = await UserModal.findOne({ email: email });
  // Send Error if yes otherwise create new account and save user inside DB
  if (existingUser)
    return sendErrorRes(
      res,
      "Unauthorized request, email is already in use!",
      401
    );

  const user = await UserModal.create({ name, email, password });

  // user.comparePassword(password);

  // Generate and Store verification token in database
  const token = crypto.randomBytes(36).toString("hex");

  await AuthVerficationTokenModal.create({
    owner: user._id,
    token,
    createdAt: Date.now(),
  });

  // Send verification email to user email
  const link = `http://localhost:9000/verify?id=${user._id}&token=${token}`;

  const transport = nodemailer.createTransport({
    host: "sandbox.smtp.mailtrap.io",
    port: 2525,
    auth: {
      user: "639daddeb78c87",
      pass: "a4b507195c96a4",
    },
  });

  await transport.sendMail({
    from: "verification@myapp.com",
    to: user.email,
    html: `<h1>Please click on <a href="${link}">this link</a> to verify your account.</h1>`,
  });

  // Send message back to check email inbox.
  res.json({ message: "Please check your inbox." });
};

export const verifyEmail: RequestHandler = async (req, res) => {
  const { id, token } = req.body;

  const authToken = await AuthVerficationTokenModal.findOne({
    owner: id,
  });
  if (!authToken) return sendErrorRes(res, "Unauthorized request", 403);

  const isMatched = authToken.compareToken(token);
  if (!isMatched)
    return sendErrorRes(res, "Unauthorized request, invalid token", 403);

  await UserModal.findByIdAndUpdate(id, { varified: true });

  await AuthVerficationTokenModal.findByIdAndDelete(authToken._id);

  res.json({ message: "Email verified successfully" });
};

export const signIn: RequestHandler = async (req, res) => {
  const { email, password } = req.body;

  const user = await UserModal.findOne({ email });
  if (!user) return sendErrorRes(res, "Invalid email or password", 403);

  const isMatched = user.comparePassword(password);
  if (!isMatched) return sendErrorRes(res, "Invalid email or password", 403);

  const payLoad = { id: user._id };

  const accessToken = jwt.sign(payLoad, "secret", {
    expiresIn: "15m",
  });
  const refreshToken = jwt.sign(payLoad, "secret");

  if (!user.tokens) user.tokens = [refreshToken];
  else user.tokens.push(refreshToken);

  await user.save();

  res.json({
    profile: {
      id: user._id,
      email: user.email,
      name: user.name,
      verified: user.verified,
    },
    tokens: { refresh: refreshToken, access: accessToken },
  });
};

export const sendProfile: RequestHandler = (req, res) => {
  res.json({ profile: req.user });
};
