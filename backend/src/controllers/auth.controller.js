import { generateToken } from "../lib/utils.js";
import User from "../models/user.model.js";
import bcrypt from "bcryptjs";
import { userSignupValidator } from "../validators/user.validator.js";

export const signup = async (req, res) => {
  const { email, fullName, password } = req.body;

  const { error } = userSignupValidator({ email, fullName, password });

  if (error) {
    return res.status(400).json({ success: false, message: error.details[0].message });
  }

  try {
    const userAlreadyExists = await User.findOne({ email });

    if (userAlreadyExists) {
      return res.status(409).json({ success: false, message: "User already exists" });
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    const user = new User({ email, fullName, password: hashedPassword });

    if (user) {
      generateToken(user._id, res);
      await user.save();

      res.status(201).json({
        success: true,
        message: "User created successfully",
        user: {
          _id: user._id,
          email: user.email,
          fullName: user.fullName,
          profilePic: user.profilePic,
        },
      });
    } else {
      res.status(400).json({ success: false, message: "Invalid user data" });
    }
  } catch (error) {
    console.error("signup controller -> error", error.message);
    res.status(500).json({ success: false, message: "Internal server error" });
  }
};

export const login = async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await User.findOne({ email });

    if (!user) {
      return res.status(401).json({ success: false, message: "User does not exist" });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ success: false, message: "Invalid credentials" });
    }

    generateToken(user._id, res);

    res.status(200).json({
      success: true,
      message: "User logged in successfully",
      user: {
        _id: user._id,
        email: user.email,
        fullName: user.fullName,
        profilePic: user.profilePic,
      },
    });
  } catch (error) {
    console.error("login controller -> error", error.message);
    res.status(500).json({ success: false, message: "Internal server error" });
  }
};

export const logout = (req, res) => {
  try {
    res.cookie("jwt", "", { maxAge: 0 });
    res.status(200).json({ success: true, message: "User logged out successfully" });
  } catch (error) {
    console.error("logout controller -> error", error.message);
    res.status(500).json({ success: false, message: "Internal server error" });
  }
};
