import express from "express";
import mongoose from "mongoose";
import dotenv from "dotenv";
import jwt from "jsonwebtoken";
import cors from "cors";
import bcrypt from "bcryptjs";
import cookieParser from "cookie-parser";

const app = express();
const PORT = 3000;
app.use(express.json());
app.use(cookieParser());
app.use(cors({ origin: "http://localhost:3000", credentials: true }));
dotenv.config();

const connectDB = async () => {
  await mongoose
    .connect(process.env.DB_URI)
    .then(() => {
      console.log("DATABASE CONNECTED");
    })
    .catch(() => {
      console.log("Error in connection to database");
    });
};

const userSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true,
    unique: true,
  },
  password: {
    type: String,
    required: true,
  },
});

const user = await mongoose.model("User", userSchema);

app.post("/auth", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(409).send({
        message: "Both email and password are required",
        success: false,
      });
    }

    const userExists = await user.findOne({ email: email });

    if (userExists) {
      //user exists, login
      const auth = await bcrypt.compare(password, userExists.password);
      if (auth) {
        const accessToken = jwt.sign(
          { email, password },
          process.env.SECRET_KEY,
          { expiresIn: "15m" }
        );
        const refreshToken = jwt.sign(
          { email, password },
          process.env.SECRET_KEY,
          { expiresIn: "7d" }
        );
        res
          .cookie("accessToken", accessToken, {
            httpOnly: true,
            maxAge: 15 * 60 * 1000,
          })
          .cookie("refreshToken", refreshToken, {
            httpOnly: true,
            maxAge: 7 * 24 * 60 * 60 * 1000,
          })
          .status(200)
          .send({ message: "login successful", success: true });
      } else {
        return res
          .status(400)
          .json({ message: "Incorrect email/password", success: false });
      }
    } else {
      const hashedPassword = await bcrypt.hash(password, 10);
      const newUser = await user.create({ email, password: hashedPassword });

      const accessToken = jwt.sign(
        { email, password },
        process.env.SECRET_KEY,
        { expiresIn: "15m" }
      );
      const refreshToken = jwt.sign(
        { email, password },
        process.env.SECRET_KEY,
        { expiresIn: "7d" }
      );
      return res
        .cookie("accessToken", accessToken, {
          httpOnly: true,
          maxAge: 15 * 60 * 1000,
        })
        .cookie("refreshToken", refreshToken, {
          httpOnly: true,
          maxAge: 7 * 24 * 60 * 60 * 1000,
        })
        .send({ message: "User created, logged in", success: true, newUser });
    }
  } catch (error) {
    console.log(error.message);
    return res
      .status(500)
      .send({ message: "internal server error", success: false });
  }
});

const verifyUser = (req, res, next) => {
  try {
    const token = req.cookies.refreshToken;
    if (!token) {
      return res
        .status(400)
        .send({ message: "token not present, logged in", success: false });
    }
    jwt.verify(token, process.env.SECRET_KEY, (err, decoded) => {
      if (err) {
        return res
          .status(500)
          .send({ message: "invalid token, login again", success: false });
      }
      req.user = decoded;
      next();
    });
  } catch (error) {
    console.log(error.message);
    return res.status(400).send({
      message: "User authentication failed",
      success: false,
    });
  }
};

app.get("/profile", verifyUser, (req, res) => {
  try {
    return res.status(200).send({
      message: "user authorized",
      success: true,
      user: req.user,
    });
  } catch (error) {
    console.log(error.message);
    return res
      .status(500)
      .send({ message: "Internal Server error", success: false });
  }
});

app.listen(PORT, () => {
  connectDB();
  console.log("Server running at port", PORT);
});
