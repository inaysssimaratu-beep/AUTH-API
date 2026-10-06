import { Request, Response } from "express";
import bcrypt from "bcrypt";
import prisma from "../lib/prisma";
import jwt from "jsonwebtoken";
import crypto from "crypto";

export const register = async (req: Request, res: Response) => {
  try {
    const { name, email, password, passwordConfirmation } = req.body;

    if (!name || !email || !password || !passwordConfirmation) {
      return res.status(400).json({
        message: "Semua field wajib diisi"
      });
    }

    if (password !== passwordConfirmation) {
      return res.status(400).json({
        message: "Password confirmation tidak sama"
      });
    }

    const existingUser = await prisma.user.findUnique({
      where: { email }
    });

    if (existingUser) {
      return res.status(400).json({
        message: "Email sudah digunakan"
      });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const user = await prisma.user.create({
      data: {
        name,
        email,
        password: hashedPassword
      }
    });

    return res.status(201).json({
      message: "Register berhasil",
      data: {
        id: user.id,
        name: user.name,
        email: user.email
      }
    });

  } catch (error) {
    console.error(error);

    return res.status(500).json({
      message: "Terjadi kesalahan pada server"
    });
  }
};

export const login = async (req: Request, res: Response) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        message: "Email dan password wajib diisi"
      });
    }

    const user = await prisma.user.findUnique({
      where: { email }
    });

    if (!user) {
      return res.status(401).json({
        message: "Email atau password salah"
      });
    }

    const isPasswordValid = await bcrypt.compare(
      password,
      user.password
    );

    if (!isPasswordValid) {
      return res.status(401).json({
        message: "Email atau password salah"
      });
    }

    const token = jwt.sign(
      {
        id: user.id,
        email: user.email
      },
      process.env.JWT_SECRET || "secret-key",
      {
        expiresIn: "1d"
      }
    );

    return res.status(200).json({
      message: "Login berhasil",
      token,
      user: {
        id: user.id,
        name: user.name,
        email: user.email
      }
    });

  } catch (error) {
    console.error(error);

    return res.status(500).json({
      message: "Terjadi kesalahan pada server"
    });
  }
};

export const forgotPassword = async (req: Request, res: Response) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({
        message: "Email wajib diisi"
      });
    }

    const user = await prisma.user.findUnique({
      where: { email }
    });

    if (!user) {
      return res.status(404).json({
        message: "Email tidak ditemukan"
      });
    }

    const resetToken = crypto.randomBytes(32).toString("hex");

    const resetTokenExpiresAt = new Date(
      Date.now() + 15 * 60 * 1000
    );

    await prisma.user.update({
      where: { email },
      data: {
        resetToken,
        resetTokenExpiresAt
      }
    });

    return res.status(200).json({
      message: "Reset token berhasil dibuat",
      resetToken
    });

  } catch (error) {
    console.error(error);

    return res.status(500).json({
      message: "Terjadi kesalahan pada server"
    });
  }
};

export const resetPassword = async (req: Request, res: Response) => {
  try {
    const {
      token,
      password,
      passwordConfirmation
    } = req.body;

    if (!token || !password || !passwordConfirmation) {
      return res.status(400).json({
        message: "Semua field wajib diisi"
      });
    }

    if (password !== passwordConfirmation) {
      return res.status(400).json({
        message: "Password confirmation tidak sama"
      });
    }

    const user = await prisma.user.findFirst({
      where: {
        resetToken: token,
        resetTokenExpiresAt: {
          gt: new Date()
        }
      }
    });

    if (!user) {
      return res.status(400).json({
        message: "Token tidak valid atau sudah expired"
      });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    await prisma.user.update({
      where: {
        id: user.id
      },
      data: {
        password: hashedPassword,
        resetToken: null,
        resetTokenExpiresAt: null
      }
    });

    return res.status(200).json({
      message: "Password berhasil direset"
    });

  } catch (error) {
    console.error(error);

    return res.status(500).json({
      message: "Terjadi kesalahan pada server"
    });
  }
};