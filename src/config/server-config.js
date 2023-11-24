const dotenv = require('dotenv');

dotenv.config();

module.exports = {
    PORT: process.env.PORT,
    SALT_ROUND: process.env.SALT_ROUND,
    JWT_SECRET: process.env.JWT_SECRET,
    JWT_EXPIRY: process.env.JWT_EXPIRY,
    FLIGHT_SERVICE: process.env.FLIGHT_SERVICE,
    BOOKING_SERVICE: process.env.BOOKING_SERVICE
}