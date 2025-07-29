import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import { Pool } from "pg";
import admin from "firebase-admin";
import { v2 as cloudinary } from "cloudinary";
import multer from "multer";

// Load environment variables
dotenv.config();

const { DATABASE_URL } = process.env;

// Cloudinary configuration
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

// Configure Multer for handling file uploads (memory storage)
const storage = multer.memoryStorage();
const upload = multer({
  storage: storage,
  limits: {
    fileSize: 10 * 1024 * 1024, // 10MB limit
  },
  fileFilter: (req, file, cb) => {
    // Only allow image files
    if (file.mimetype.startsWith("image/")) {
      cb(null, true);
    } else {
      cb(new Error("Only image files are allowed!"), false);
    }
  },
});

// Helper function to upload image to Cloudinary
const uploadToCloudinary = (fileBuffer, folder = "deals") => {
  return new Promise((resolve, reject) => {
    cloudinary.uploader
      .upload_stream(
        {
          resource_type: "image",
          folder: folder,
          transformation: [
            { width: 800, height: 600, crop: "limit" },
            { quality: "auto" },
            { format: "auto" },
          ],
        },
        (error, result) => {
          if (error) {
            reject(error);
          } else {
            resolve(result);
          }
        }
      )
      .end(fileBuffer);
  });
};

// Firebase service account setup
const serviceAccount = {
  type: "service_account",
  project_id: "capstone-deals-app",
  private_key_id: process.env.FIREBASE_PRIVATE_KEY_ID,
  private_key: process.env.FIREBASE_PRIVATE_KEY?.replace(/\\n/g, "\n"),
  client_email: process.env.FIREBASE_CLIENT_EMAIL,
  client_id: process.env.FIREBASE_CLIENT_ID,
  auth_uri: process.env.FIREBASE_AUTH_URI,
  token_uri: process.env.FIREBASE_TOKEN_URI,
  auth_provider_x509_cert_url: process.env.FIREBASE_AUTH_PROVIDER_X509_CERT_URL,
  client_x509_cert_url: process.env.FIREBASE_CLIENT_X509_CERT_URL,
  universe_domain: "googleapis.com",
};

// Initialize Firebase Admin
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

// Check if variables are loaded (these console.logs were in your original code)
console.log("Private Key ID:", process.env.FIREBASE_PRIVATE_KEY_ID);
console.log("Private Key exists:", !!process.env.FIREBASE_PRIVATE_KEY);
console.log("Client Email:", process.env.FIREBASE_CLIENT_EMAIL);

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

// Test Firebase connection
app.get("/firebase-test", async (req, res) => {
  try {
    // Just test if admin is initialized
    const auth = admin.auth();
    res.json({
      message: "Firebase initialized successfully!",
      projectId: admin.app().options.projectId,
    });
  } catch (error) {
    res.status(500).json({
      message: "Firebase initialization failed",
      error: error.message,
    });
  }
});

export default app;
