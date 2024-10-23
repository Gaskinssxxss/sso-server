const User = require("../models/User");
const jwt = require("jsonwebtoken");
const { validateUser } = require("../utils/validateRequest");

const generateToken = (user) => {
  return jwt.sign({ id: user._id, role: user.role }, process.env.JWT_SECRET, {
    expiresIn: "15m",
  });
};

const generateRefreshToken = (user) => {
  return jwt.sign({ id: user._id }, process.env.JWT_SECRET, {
    expiresIn: "7d",
  });
};

exports.register = async (req, res, next) => {
  const { error } = validateUser(req.body);
  if (error) return next({ status: 400, message: error.details[0].message });

  const { username, email, password, role } = req.body;

  try {
    const user = new User({ username, email, password, role });
    await user.save();

    const accessToken = generateToken(user);
    const refreshToken = generateRefreshToken(user);

    user.refreshToken = refreshToken;
    await user.save();

    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });
    res
      .status(201)
      .json({ accessToken, user: { id: user._id, username, email, role } });
  } catch (err) {
    next({ status: 500, message: "Server error" });
  }
};

exports.login = async (req, res, next) => {
  const { email, password } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user || !(await user.comparePassword(password))) {
      return next({ status: 401, message: "Invalid email or password" });
    }

    const accessToken = generateToken(user);
    const refreshToken = generateRefreshToken(user);

    user.refreshToken = refreshToken;
    await user.save();

    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });
    res.status(200).json({
      message: "Login successful",
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        role: user.role,
      },
      accessToken,
      redirectTo: "/api/auth/hello",
    });
  } catch (err) {
    next({ status: 500, message: "Server error" });
  }
};

exports.refreshToken = async (req, res, next) => {
  const { refreshToken } = req.cookies;
  if (!refreshToken)
    return next({ status: 401, message: "No refresh token found" });

  try {
    const decoded = jwt.verify(refreshToken, process.env.JWT_SECRET);
    const user = await User.findById(decoded.id);
    if (!user || user.refreshToken !== refreshToken) {
      return next({ status: 403, message: "Invalid refresh token" });
    }

    const newAccessToken = generateToken(user);
    res.status(200).json({ accessToken: newAccessToken });
  } catch (err) {
    next({ status: 403, message: "Invalid or expired refresh token" });
  }
};

exports.logout = async (req, res, next) => {
  const { refreshToken } = req.cookies;
  if (!refreshToken)
    return next({ status: 400, message: "No refresh token found" });

  try {
    const user = await User.findOne({ refreshToken });
    if (!user) return next({ status: 404, message: "User not found" });

    user.refreshToken = null;
    await user.save();

    res.clearCookie("refreshToken");
    res.status(200).json({ message: "Logout successful" });
  } catch (err) {
    next({ status: 500, message: "Server error" });
  }
};
