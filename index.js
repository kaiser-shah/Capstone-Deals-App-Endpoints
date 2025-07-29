import express from "express";
import cors from "cors";
import dotenv from "dotenv";

// Load environment variables
dotenv.config();

const app = express();

// Basic middleware
app.use(
  cors({
    origin: ["https://capstone-deals-app.vercel.app", "http://localhost:3000"],
    credentials: true,
  })
);

app.use(express.json());

// Test routes
app.get("/", (req, res) => {
  res.json({ message: "Minimal server is working!" });
});

app.get("/test", (req, res) => {
  res.json({
    message: "Test route works!",
    timestamp: new Date().toISOString(),
    hasDbUrl: !!process.env.DATABASE_URL,
    hasCloudinary: !!process.env.CLOUDINARY_CLOUD_NAME,
  });
});

export default app;
