require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const helmet = require("helmet");
const cors = require("cors");
const morgan = require("morgan");
const cookieParser = require("cookie-parser");
const csurf = require("csurf");

const limiter = require("./middleware/rateLimiter");
const authRoutes = require("./routes/authRoutes");
const logger = require("./config/logger");
const errorHandler = require("./middleware/errorHandler");

const app = express();

app.use(helmet());
const corsOptions = {
  origin: "http://localhost:8080",
  optionsSuccessStatus: 200,
  credentials: true,
};
app.use(cors(corsOptions));
app.use(express.json());
app.use(cookieParser());

const csrfProtection = csurf({ cookie: true });
app.use(csrfProtection);

app.use(
  morgan("combined", {
    stream: { write: (message) => logger.info(message.trim()) },
  })
);

app.use(limiter);

app.get("/csrf-token", (req, res) => {
  res.json({ csrfToken: req.csrfToken() });
});

app.use("/api/auth", authRoutes);

mongoose
  .connect(process.env.MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => {
    logger.info("MongoDB connected");
    app.listen(process.env.PORT, () =>
      logger.info(`Server running on port ${process.env.PORT}`)
    );
  })
  .catch((err) => logger.error(`Database connection error: ${err.message}`));

app.use(errorHandler);
