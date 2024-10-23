const express = require("express");
const {
  register,
  login,
  refreshToken,
  logout,
} = require("../controllers/authController");
const { protect } = require("../middleware/authMiddleware");
const loginLimiter = require("../middleware/LoginRateLimiter");

const router = express.Router();

router.post("/register", register);
router.post("/login", loginLimiter, login);
router.post("/refresh-token", refreshToken);
router.post("/logout", logout);

router.get("/hello", protect, (req, res) => {
  res.status(200).send("Hello World");
});

module.exports = router;
