import { RequestHandler } from "express";
import UserModal from "src/modals/user";
import crypto from "crypto";
import AuthVerficationTokenModal from "src/modals/authVerficationToken";
import { sendErrorRes } from "src/utils/helper";
import jwt from "jsonwebtoken";
import mail from "src/utils/mail";

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
  const link = `${process.env.VERIFICATION_LINK}?id=${user._id}&token=${token}`;

  await mail.sendEmailVerification(email, link);

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

  const accessToken = jwt.sign(payLoad, process.env.JWT_SECRET!, {
    expiresIn: "15m",
  });
  const refreshToken = jwt.sign(payLoad, process.env.JWT_SECRET!);

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

export const generateVerfificationLink: RequestHandler = async (req, res) => {
  const { id } = req.user;

  const token = crypto.randomBytes(36).toString("hex");

  const link = `${process.env.VERIFICATION_LINK}?id=${id}&token=${token}`;

  await AuthVerficationTokenModal.findOneAndDelete({ owner: id });

  await AuthVerficationTokenModal.create({ owner: id, token });

  await mail.sendEmailVerification(req.user.email, link);
  res.json({ message: "Please check your inbox." });
};

export const getAccessToken: RequestHandler = async (req, res) => {
  const { refreshToken } = req.body;

  if (!refreshToken) return sendErrorRes(res, "Unauthorized request", 403);

  const payLoad = jwt.verify(refreshToken, process.env.JWT_SECRET!) as {
    id: string;
  };

  if (!payLoad.id) {
    return sendErrorRes(res, "Unauthorized request", 401);
  } else {
    const user = await UserModal.findOne({
      _id: payLoad.id,
      tokens: refreshToken,
    });

    if (!user) {
      // user is compromised, remove all previous tokens
      await UserModal.findByIdAndUpdate(payLoad.id, { tokens: [] });
      return sendErrorRes(res, "Unauthorized request", 401);
    }

    const newAccessToken = jwt.sign({ id: user._id }, process.env.JWT_SECRET!, {
      expiresIn: "15m",
    });
    const newRefreshToken = jwt.sign({ id: user._id }, process.env.JWT_SECRET!);

    const filterredToken = user.tokens.filter((tkn) => tkn !== refreshToken);
    user.tokens = filterredToken;
    user.tokens.push(newRefreshToken);
    await user.save();

    res.json({ tokens: { refresh: newRefreshToken, access: newAccessToken } });
  }
};

export const signOut: RequestHandler = async (req, res) => {
  const { refreshToken } = req.body;
  const user = await UserModal.findOne({
    _id: req.user.id,
    tokens: refreshToken,
  });
  if (!user) return sendErrorRes(res, "Unauthorized request", 403);

  const newTokens = user.tokens.filter((tkn) => tkn !== req.body.refreshToken);

  user.tokens = newTokens;

  await user.save();

  res.send();
};
