import e, { RequestHandler } from "express";
import { sendErrorRes } from "src/utils/helper";
import jwt, { JsonWebTokenError, TokenExpiredError } from "jsonwebtoken";
import UserModal from "src/modals/user";

declare global {
  namespace Express {
    interface Request {
      user: {
        id: string;
        name: string;
        email: string;
        verified: boolean;
      };
    }
  }
}

export const isAuth: RequestHandler = async (req, res, next) => {
  try {
    const authToken = req.headers.authorization;
    if (!authToken) return sendErrorRes(res, "Unauthorized request", 403);

    const token = authToken.split("Bearer ")[1];

    const payload = jwt.verify(token, "secret") as { id: string };

    const user = await UserModal.findById(payload.id);
    if (!user) return sendErrorRes(res, "Unauthorized request", 403);

    req.user = {
      id: user._id.toString(),
      name: user.name,
      email: user.email,
      verified: user.verified,
    };

    next();
  } catch (error) {
    if (error instanceof TokenExpiredError)
      return sendErrorRes(res, "Session Expired", 401);

    if (error instanceof JsonWebTokenError)
      return sendErrorRes(res, "unauthorized access", 401);
    next(error);
  }
};
