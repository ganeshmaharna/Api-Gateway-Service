const { StatusCodes } = require("http-status-codes");
const { UserRepository } = require("../repositories");
const AppError = require("../utils/errors/app-error");
const { Auth } = require("../utils/common");
const userRepository = new UserRepository();

async function create(data) {
  try {
    const user = await userRepository.create(data);
    return user;
  } catch (error) {
    if (
      error.name == "SequelizeValidationError" ||
      error.name == "SequelizeUniqueConstraintError"
    ) {
      let explanation = [];
      error.errors.forEach((err) => {
        explanation.push(err.message);
      });
      throw new AppError(explanation,StatusCodes.BAD_REQUEST);
    }
    throw new AppError(
      "Cannot create a new user object",
      StatusCodes.INTERNAL_SERVER_ERROR
    );
  }
}
async function signin(data) {
  try {
    const user = await userRepository.getUserByEmail(data.email);
    console.log("This is Auth ", Auth);
    if (!user) {
      throw new AppError(
        "No user found for the given email",
        StatusCodes.NOT_FOUND
      );
    }
    const passwordMatch = Auth.checkPassword(data.password, user.password);
    console.log("password match", passwordMatch);
    if (!passwordMatch) {
      throw new AppError("Invalid password", StatusCodes.BAD_REQUEST);
    }
    const jwt = Auth.createToken({ id: user.id, email: user.email });
    console.log("This is the jwt token ", jwt);
    return jwt;
  } catch (error) {
    if (error instanceof AppError) throw error;
    console.log(error);
    throw new AppError(
      "Something went wrong",
      StatusCodes.INTERNAL_SERVER_ERROR
    );
  }
}
async function isAuthenticated(token) {
  try {
    if (!token) {//If here error happens then instance  of AppError called revise this
      throw new AppError("Missing JWT token", StatusCodes.BAD_REQUEST);
    }
    const response = Auth.verifyToken(token);
    // console.log("This is the response ",response);
    const user = await userRepository.get(response.id);
    if (!user) {
      throw new AppError("No user found", StatusCodes.NOT_FOUND);
    }
    return user.id;
  } catch (error) {
    // console.log("This is the response1 ",error);
    if (error instanceof AppError) throw error;//This is imp 
    if (error.name === "JsonWebTokenError") {
      throw new AppError("Invalid JWT token", error.errorname,StatusCodes.BAD_REQUEST);
    }
    if(error.name == 'TokenExpiredError') {
        throw new AppError('JWT token expired', StatusCodes.BAD_REQUEST);
    }
    console.log(error);
    throw new AppError(
      "Something went wrong",
      StatusCodes.INTERNAL_SERVER_ERROR
    );
  }
}

module.exports = {
  create,
  signin,
  isAuthenticated
};
