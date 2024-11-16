import { Request, Response } from "express";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { setTokenInCookies, setUserIdInCookies } from "../middlewares/auth";
import {
  registrationSchema,
  loginSchema,
  updateUserSchema,
} from "../schemas/userSchemas";

import User from "../models/User";

import fs from "fs";
import csv from "csv-parser";

const JWT = process.env.JWT_SECRET as string;

// Register a new user
export const registerUser = async (req: Request, res: Response) => {
  const result = registrationSchema.safeParse(req.body);

  if (!result.success) {
    return res.status(400).json({ errors: result.error.errors });
  }

  try {
    const { firstName, lastName, email, password } = result.data;
    const hashedPassword = await bcrypt.hash(password, 10);
    const token = jwt.sign({ email }, JWT, { expiresIn: "1h" });

    // Create the user in the database
    const user = await User.create({
      firstName,
      lastName,
      email,
      password: hashedPassword,
      token: token,
    });

    console.log("User created successfully");

    setTokenInCookies(res, token);
    setUserIdInCookies(res, user.id);

    res.status(201).json({
      id: user.id,
      firstName: user.firstName,
      lastName: user.lastName,
      email: user.email,
    });
  } catch (error) {
    console.error("Error during registration process:", error);
    res
      .status(500)
      .json({ error: "Internal server error occurred during registration." });
  }
};

export const registerUsersFromCSV = async (req: Request, res: Response) => {
  const users: {
    firstName: string;
    lastName: string;
    email: string;
    password: string;
  }[] = [];

  const errorsArray: string[] = [];
  const emailSet = new Set<string>();
  const filePath = "/home/node/app/unique_usersErrors.csv";

  fs.createReadStream(filePath)
    .pipe(csv())
    .on("data", (row) => {
      try {
        const { name, surname, email } = row;

        if (!name || !surname || !email) {
          errorsArray.push(
            `Missing required fields in row: ${JSON.stringify(
              row
            )} for surname ${surname} and email ${email}`
          );
          return;
        }

        if (emailSet.has(email)) {
          errorsArray.push(
            `Duplicate email ${email} found in row(s): ${JSON.stringify(row)}`
          );
          return;
        }

        const result = registrationSchema.safeParse({
          firstName: name,
          lastName: surname,
          email: email,
          password: "Password123",
        });

        if (result.success) {
          users.push(result.data);
          emailSet.add(email);
        } else {
          errorsArray.push(
            `Invalid data in row: ${JSON.stringify(row)} for email ${email}`
          );
        }
      } catch (error) {
        console.error("Error during registration process:", error);
        res.status(500).json({
          error: "Internal server error occurred during registration.",
        });
      }
    })
    .on("end", async () => {
      try {
        // Check for existing users in the database
        const existingUsers = await User.findAll({
          where: { email: Array.from(emailSet) },
        });

        const existingEmails = new Set(existingUsers.map((user) => user.email));
        existingEmails.forEach((email) => {
          errorsArray.push(`User with email ${email} already exists.`);
        });

        const newUsers = users.filter(
          (user) => !existingEmails.has(user.email)
        );

        const createdUsers = [];
        for (const userData of newUsers) {
          const hashedPassword = await bcrypt.hash(userData.password, 10);
          const token = jwt.sign({ email: userData.email }, JWT, {
            expiresIn: "1h",
          });

          const user = await User.create({
            firstName: userData.firstName,
            lastName: userData.lastName,
            email: userData.email,
            password: hashedPassword,
            token: token,
          });

          createdUsers.push(user);
        }

        if (errorsArray.length > 0) {
          console.log("Errors during user creation:", errorsArray);
        }

        res.status(201).json({
          "Users created": createdUsers,
          Errors: errorsArray,
        });
      } catch (error) {
        console.error("Error during bulk registration process:", error);
        res.status(500).json({
          error: "Internal server error occurred during bulk registration.",
        });
      }
    });
};

// Login a user
export const loginUser = async (req: Request, res: Response) => {
  const result = loginSchema.safeParse(req.body);

  if (!result.success) {
    return res.status(400).json({ errors: result.error.errors });
  }
  try {
    const { email, password } = result.data;
    const user = await User.findOne({ where: { email } });
    if (!user) {
      return res.status(401).json({ error: "Email or password invalid" });
    }
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(401).json({ error: "Email or password invalid" });
    }

    const token = jwt.sign({ email }, JWT, { expiresIn: "1h" });

    setTokenInCookies(res, token);
    setUserIdInCookies(res, user.id);

    res.status(200).json({
      id: user.id,
      firstName: user.firstName,
      lastName: user.lastName,
      email: user.email,
    });
  } catch (error) {
    console.error("Error during login process:", error);
    res
      .status(500)
      .json({ error: "Internal server error occurred during login." });
  }
};

// Logout a user
export const logoutUser = async (req: Request, res: Response) => {
  res.clearCookie("token");
  res.clearCookie("userId");
  res.status(200).send("Logout successful");
};

// Get a user's info by ID   authenticateJWT refreshToken,
export const getUserInfo = async (req: any, res: any) => {
  try {
    const user = await User.findOne({
      where: { id: req.params.userId, showProfile: true },
    });
    if (!user) {
      return res.status(404).json({ error: "User not found." });
    }
    const responseData = {
      id: user.id,
      firstName: user.firstName,
      lastName: user.lastName,
      email: user.email,
      age: user.age,
      description: user.description,
      profilePicture: user.profilePicture,
      showProfile: user.showProfile,
    };

    res.status(200).json(responseData);
  } catch (error) {
    console.error("Error retrieving user info:", error);
    res.status(500).json({ error: "Failed to retrieve user info." });
  }
};

// Update a user's info by ID
export const updateUser = async (req: any, res: any) => {
  const result = updateUserSchema.safeParse(req.body);

  if (!result.success) {
    return res.status(400).json({ errors: result.error.errors });
  }
  try {
    const user = await User.findOne({ where: { id: req.params.userId } });
    if (!user) {
      return res.status(404).json({ error: "User not found." });
    }
    await user.update(result.data);
    res.status(200).json({
      id: user.id,
      firstName: user.firstName,
      lastName: user.lastName,
      email: user.email,
      age: user.age,
      description: user.description,
      profilePicture: user.profilePicture,
      showProfile: user.showProfile,
    });
  } catch (error) {
    console.error("Error updating user info:", error);
    res.status(500).json({ error: "Failed to update user info." });
  }
};

// Retrieve all users from databse whose profiles are public
export const getPublicUsers = async (req: any, res: any) => {
  try {
    const users = await User.findAll({
      where: { showProfile: true },
    });
    res.status(200).json(users);
    console.log("Retrieved users");
  } catch (error) {
    console.error("Error retrieving users:", error);
    res.status(500).json({ error: "Failed to retrieve users." });
  }
};
