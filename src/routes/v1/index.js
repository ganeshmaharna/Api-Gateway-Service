const express = require("express");

const { InfoController } = require("../../controllers");
const userRouter = require("./user-routes");
const {AuthRequestMiddleware} = require("../../middlewares");

const router = express.Router();
router.get("/info",AuthRequestMiddleware.checkAuth,InfoController.info);
router.use("/user", userRouter);

module.exports = router;
