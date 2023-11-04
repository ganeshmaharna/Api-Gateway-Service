const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { StatusCodes } = require("http-status-codes");
const AppError = require("../errors/app-error");

const { ServerConfig } = require('../../config');
function checkPassword(plainPassword, encryptedPassword) {
    try {
        return bcrypt.compareSync(plainPassword, encryptedPassword);
    } catch(error) {
        console.log(error);
        throw error;
    }
}

function createToken(input) {
    try {
        return jwt.sign(input, ServerConfig.JWT_SECRET, {expiresIn: ServerConfig.JWT_EXPIRY});
    } catch(error) {
        console.log(error);
        throw error;
    }
}
function verifyToken(token){
    try {
        const decode = jwt.verify(token,ServerConfig.JWT_SECRET)
        return decode;
    } catch (error) {
        if (error instanceof jwt.JsonWebTokenError) {
            throw new AppError("Invalid JWT token", error.errorname,StatusCodes.BAD_REQUEST);
          } else {
            console.log("The error is ",error);
            throw error; // Re-throw other errors
          }
    }
}

module.exports = {
    checkPassword,
    createToken,
    verifyToken
}