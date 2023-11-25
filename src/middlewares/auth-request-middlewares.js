const { StatusCodes } = require("http-status-codes");

const { ErrorResponse } = require("../utils/common");
const AppError = require("../utils/errors/app-error");
const { UserService } = require("../services");

function validateAuthRequest(req, res, next) {
  if (!req.body.email) {
    ErrorResponse.message =
      "Something went wrong while authenticating the user";
    ErrorResponse.error = new AppError(
      ["User email name not found in the incoming request in the correct form"],
      StatusCodes.BAD_REQUEST
    );
    return res.status(StatusCodes.BAD_REQUEST).json(ErrorResponse);
  }
  if (!req.body.password) {
    ErrorResponse.message =
      "Something went wrong while authenticating the user";
    ErrorResponse.error = new AppError(
      ["User password not found in the incoming request in the correct form"],
      StatusCodes.BAD_REQUEST
    );
    return res.status(StatusCodes.BAD_REQUEST).json(ErrorResponse);
  }
  next();
}
async function checkAuth(req, res, next) {
  try {
    const response = await UserService.isAuthenticated(
      req.headers["x-access-token"]
    );
    if (response) {
      req.user = response; // setting the user id in the req object
      next();
    }
  } catch (error) {
    ErrorResponse.message =
      "Something went wrong while checking signin the user";
    return res.status(StatusCodes.BAD_REQUEST).json(ErrorResponse);
  }
}
async function isAdmin(req, res, next) {
  const response = await UserService.isAdmin(req.user);
  if (!response) {
    return res
      .status(StatusCodes.UNAUTHORIZED)
      .json({ message: "User not authorized for this action" });
  }
  next();
}

module.exports = {
  validateAuthRequest,
  checkAuth,
  isAdmin,
};
