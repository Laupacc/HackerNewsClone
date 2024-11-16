import express from "express";
import { authenticateJWT, refreshToken } from "../middlewares/auth";
import {
  registerUser,
  loginUser,
  logoutUser,
  getUserInfo,
  updateUser,
  getPublicUsers,
  registerUsersFromCSV,
} from "../controllers/userController";

const router = express.Router();

// Register a new user
router.post("/register", registerUser);

// Login a user
router.post("/login", loginUser);

// Logout a user
router.post("/logout", logoutUser);

// Get a user's info by ID
router.get("/:userId/userInfo", authenticateJWT, refreshToken, getUserInfo);

// Update a user's info by ID
router.put("/:userId/userInfo", authenticateJWT, refreshToken, updateUser);

// Retrieve all users from databse whose profiles are public
router.get("/allUsersPublicProfiles", getPublicUsers);

// Register users from CSV file
router.post("/registerUsersFromCSV", registerUsersFromCSV);

export default router;
