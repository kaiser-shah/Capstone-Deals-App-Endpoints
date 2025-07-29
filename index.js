import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import { Pool } from "pg";

// Load environment variables
dotenv.config();

const { DATABASE_URL } = process.env;

// Setup connection pool for postgreSQL
const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: {
    rejectUnauthorized: false,
  },
});

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

// Test database connection
app.get("/db-test", async (req, res) => {
  try {
    const client = await pool.connect();
    const result = await client.query("SELECT version()");
    client.release();
    res.json({
      message: "Database connection successful!",
      version: result.rows[0].version,
    });
  } catch (error) {
    res.status(500).json({
      message: "Database connection failed",
      error: error.message,
    });
  }
});

export default app;
