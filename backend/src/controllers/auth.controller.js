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

export const login = (req, res) => {
  res.send("Login route");
};

export const logout = (req, res) => {
  res.send("Logout route");
};
