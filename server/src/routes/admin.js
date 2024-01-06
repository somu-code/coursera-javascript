import { Router } from "express";
import bcrypt from "bcrypt";
import { Admin } from "../models/admin-model.js";
import Course from "../models/course-model.js";
import {
  generateAdminJWT,
  authenticateAdminJWT,
} from "../jwt-auth/admin-auth.js";
import mongoose from "mongoose";

export const adminRouter = Router();

const saltRounds = 8;

adminRouter.post("/signup", async (req, res) => {
  try {
    const { email, password } = await req.body;
    const adminData = await Admin.findOne({ email });
    if (adminData) {
      return res.status(403).json({ message: "Admin email already exists" });
    }
    const hashedPassword = await bcrypt.hash(password, saltRounds);
    const newAdmin = new Admin({ email, password: hashedPassword });
    await newAdmin.save();
    return res.status(201).json({
      message: "Admin created successfully",
    });
  } catch (error) {
    console.error(error);
    res.sendStatus(500);
  }
});

adminRouter.post("/signin", async (req, res) => {
  try {
    const { email, password } = await req.body;
    const adminData = await Admin.findOne({ email });
    if (!adminData) {
      return res.status(404).json({ message: "Email not found" });
    }
    const isPasswordMath = await bcrypt.compare(password, adminData.password);
    if (!isPasswordMath) {
      return res.status(401).json({ message: "Invalid credentials" });
    }
    const adminPayload = {
      id: adminData.id,
      email: adminData.email,
      role: adminData.role,
    };
    const adminToken = generateAdminJWT(adminPayload);
    res.cookie("adminAccessToken", adminToken, {
      domain: "localhost",
      path: "/",
      maxAge: 60 * 60 * 1000,
      secure: true,
      sameSite: "strict",
    });
    return res.status(201).json({ message: "Signin in successful" });
  } catch (error) {
    console.error(error);
    res.sendStatus(500);
  }
});

adminRouter.get("/profile", authenticateAdminJWT, async (req, res) => {
  try {
    const admin = await req.admin;
    res.json(admin);
  } catch (error) {
    console.error(error);
    res.sendStatus(500);
  }
});

adminRouter.post("/logout", authenticateAdminJWT, async (_req, res) => {
  try {
    res.clearCookie("adminAccessToken");
    res.json({ message: "Logout successfully" });
  } catch (error) {
    console.error(error);
    res.sendStatus(500);
  }
});

adminRouter.delete("/delete", authenticateAdminJWT, async (req, res) => {
  try {
    const admin = await req.admin;
    // await Course.deleteMany({ owner: admin.id });
    await Admin.findByIdAndDelete(admin.id);
    res.clearCookie("adminAccessToken");
    res.json({
      message:
        "Successfully deleted admin account along all the course his/her had.",
    });
  } catch (error) {
    console.error(error);
    res.sendStatus(500);
  }
});

adminRouter.post("/create-course", authenticateAdminJWT, async (req, res) => {
  try {
    const admin = await req.admin;
    const reqBody = await req.body;
    const newCourse = { ...reqBody, owner: admin.id };
    const course = new Course(newCourse);
    await course.save();
    res.status(201).json({ message: "Course created successfully" });
  } catch (error) {
    console.error(error);
    res.sendStatus(500);
  }
});

adminRouter.get("/my-courses", authenticateAdminJWT, async (req, res) => {
  try {
    const admin = await req.admin;
    const courses = await Course.find({ owner: admin.id });
    res.json(courses);
  } catch (error) {
    console.error(error);
    res.sendStatus(500);
  }
});

adminRouter.get("/all-courses", authenticateAdminJWT, async (_req, res) => {
  try {
    const courses = await Course.find();
    res.json(courses);
  } catch (error) {
    console.error(error);
    res.sendStatus(500);
  }
});

adminRouter.put("/update-course", authenticateAdminJWT, async (req, res) => {
  try {
    const admin = await req.admin;
    const updatedCourse = await req.body;
    const isCourseIdValid = mongoose.Types.ObjectId.isValid(updatedCourse._id);
    const isOwnerIdvalid = mongoose.Types.ObjectId.isValid(updatedCourse.owner);
    if (!(isCourseIdValid && isOwnerIdvalid)) {
      return res
        .status(400)
        .json({ message: "Course _id or owner id is not valid" });
    }
    const courseData = await Course.findOne({ _id: updatedCourse._id });
    if (!courseData) {
      return res
        .status(404)
        .json({ message: "Requested course does not exixts" });
    }
    if (
      !(
        admin.id === updatedCourse.owner &&
        updatedCourse.owner === courseData.owner
      )
    ) {
      return res
        .status(403)
        .json({ message: "This course does not belong to this admin." });
    }
    await Course.findByIdAndUpdate(updatedCourse._id, updatedCourse, {
      new: true,
    });
    return res.status(201).json({ message: "Course updated successfully" });
  } catch (error) {
    console.error(error);
    res.sendStatus(500);
  }
});

adminRouter.delete("/delete-course", authenticateAdminJWT, async (req, res) => {
  try {
    const { courseId } = req.body;
    const admin = await req.admin;
    const courseData = await Course.findById(courseId);
    if (!courseData) {
      return res.status(403).json({ message: "Course does not exixts" });
    }
    if (courseData.owner === admin.id) {
      await Course.findByIdAndDelete(courseId);
      return res.json({ message: "Course deleted successfully" });
    }
    return res
      .status(403)
      .json({ message: "This course does not belong to this admin." });
  } catch (error) {
    console.log(error);
    res.sendStatus(500);
  }
});
