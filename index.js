// Importing the required libraries
import express from "express"; // Express framework for building the server
import path from "path"; // Path module for handling file paths
import cors from "cors"; // CORS module for handling cross-origin requests (important for frontend-backend communication))
import { v2 as cloudinary } from "cloudinary"; // Cloudinary for image upload and management
import multer from "multer"; // Multer for handling multipart/form-data, used for file uploads
import dotenv from "dotenv"; // Dotenv for loading environment variables from a .env file
dotenv.config(); // Dotenv module for loading environment variables from a .env file

// Initialise the express app
let app = express();

//Middleware Setup
app.use(cors());
// Enable CORS for all routes

app.use(express.json()); // Enables JSON parsing into req.body
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
  // Default folder is 'deals'
  return new Promise((resolve, reject) => {
    // Using a Promise to handle asynchronous upload
    cloudinary.uploader
      .upload_stream(
        // Uploading the image to Cloudinary
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

// Firebase Admin SDK
import admin from "firebase-admin";

// Postgres client setup
import { Pool } from "pg"; // PostgreSQL client for connecting to the database
import firebase from "firebase/compat/app"; // Firebase compatibility layer for using Firebase features
import { userInfo } from "os"; // Importing userInfo from the OS module (not used in this code)
const { DATABASE_URL, SECRET_KEY } = process.env; // Loading the database URL and secret key from the environment variables

// Initialise the express app
const serviceAccount = {
  type: "service_account",
  project_id: "capstone-deals-app",
  private_key_id: process.env.FIREBASE_PRIVATE_KEY_ID,
  private_key: process.env.FIREBASE_PRIVATE_KEY?.replace(/\\n/g, "\n"), // Convert \n to actual line breaks
  client_email: process.env.FIREBASE_CLIENT_EMAIL,
  client_id: process.env.FIREBASE_CLIENT_ID,
  auth_uri: process.env.FIREBASE_AUTH_URI,
  token_uri: process.env.FIREBASE_TOKEN_URI,
  auth_provider_x509_cert_url: process.env.FIREBASE_AUTH_PROVIDER_X509_CERT_URL,
  client_x509_cert_url: process.env.FIREBASE_CLIENT_X509_CERT_URL,
  universe_domain: "googleapis.com",
};

// Check if variables are loaded
console.log("Private Key ID:", process.env.FIREBASE_PRIVATE_KEY_ID);
console.log("Private Key exists:", !!process.env.FIREBASE_PRIVATE_KEY);
console.log("Client Email:", process.env.FIREBASE_CLIENT_EMAIL);

import { get } from "http";
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

// Try-authenticate middleware: attaches req.user if token is present and valid, else req.user = null
const tryAuthenticateToken = async (req, res, next) => {
  const authHeader = req.headers["authorization"];
  console.log("Authorization Header:", authHeader);
  if (!authHeader) {
    req.user = null;
    return next();
  }
  const token = authHeader.split(" ")[1];
  if (!token) {
    req.user = null;
    return next();
  }
  try {
    const decodedToken = await admin.auth().verifyIdToken(token);
    req.user = {
      uid: decodedToken.uid,
      email: decodedToken.email,
      // add other fields if needed
    };
  } catch (error) {
    // Invalid or expired token, treat as unauthenticated
    req.user = null;
  }
  next();
};

// Inline Middleware Function
const authenticateToken = async (req, res, next) => {
  try {
    const authHeader = req.headers["authorization"];
    const token = authHeader && authHeader.split(" ")[1]; // Extract token from "Bearer TOKEN";

    if (!token) {
      return res.status(401).json({ error: "Access token required" });
    }

    // Verify Firebase token
    const decodedToken = await admin.auth().verifyIdToken(token);
    console.log(decodedToken);
    // Add user info to request object
    req.user = {
      uid: decodedToken.uid,
      email: decodedToken.email,
      // Add other fields you need
    };

    // Continue to next middleware/route handler
    next();
  } catch (error) {
    console.error("Token verification error:", error);
    res.status(403).json({ error: "Invalid or expired token" });
  }
};

// Setup connection pool for postgreSQL
const pool = new Pool({
  connectionString: DATABASE_URL, // Use the DATABASE_URL environment variable for the connection string
  ssl: {
    rejectUnauthorized: false, // Disable SSL certificate verification (for local development only)
  },
});

// Middleware to check if the user is an admin
const isAdmin = async (req, res, next) => {
  try {
    const user_id = req.user.uid; // This comes from authenticateToken middleware
    const client = await pool.connect();

    try {
      const checkAdmin = await client.query(
        "SELECT is_admin FROM users WHERE user_id = $1",
        [user_id]
      );

      if (checkAdmin.rows.length === 0 || !checkAdmin.rows[0].is_admin) {
        return res.status(403).json({ error: "Access denied. Admins only." });
      }

      // User is an admin, continue to next middleware/route handler
      next();
    } finally {
      client.release();
    }
  } catch (error) {
    console.error("Admin check error:", error);
    res
      .status(500)
      .json({ error: "Something went wrong during admin verification." });
  }
};

// Check the PostgreSQL version to test the connection
async function getPostgreVersion() {
  const client = await pool.connect();
  try {
    const response = await client.query("SELECT version()");
    console.log(response.rows[0]);
  } finally {
    client.release(); // Release the client back to the pool
  }
}

// getPostgreVersion();

// 1. USER ENDPOINTS (Firebase Auth Integration)

// -------------- Create user record in your database after Firebase auth --------------

app.post("/addnewuser", async (req, res) => {
  const { firebase_user_id, email_verified, email, created_at, username } =
    req.body;
  const client = await pool.connect();
  try {
    // Check if the user already exists
    const userExists = await client.query(
      "SELECT * FROM users WHERE user_id = $1",
      [firebase_user_id]
    );
    if (userExists.rowCount === 0) {
      // User does not exit, add them
      const addUser = await client.query(
        "INSERT INTO users (user_id, email, username, email_verified, created_at) VALUES ($1, $2, $3, $4, $5) RETURNING *",
        [firebase_user_id, email, username, email_verified, created_at]
      );
      // Send new booking data back to client
      res.json(addUser.rows[0]);
    } else {
      // User already exists
      res.status(400).json({
        error:
          "This user already already exists. Cannot create a duplicate account.",
      });
    }
  } catch (err) {
    console.log(err.stack);
    res
      .status(500)
      .json({ error: "Something went wrong, please try again later!" });
  } finally {
    client.release();
  }
});

// Check if a user exists by email or username (public endpoint)

app.get("/user/exists", async (req, res) => {
  const { email, username } = req.query;
  const client = await pool.connect();
  try {
    if (email) {
      const result = await client.query(
        "SELECT 1 FROM users WHERE email = $1 LIMIT 1",
        [email]
      );
      return res.json({ exists: result.rows.length > 0 });
    }
    if (username) {
      const result = await client.query(
        "SELECT 1 FROM users WHERE username = $1 LIMIT 1",
        [username]
      );
      return res.json({ exists: result.rows.length > 0 });
    }
    res.status(400).json({ error: "Email or username required" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Database error" });
  } finally {
    client.release();
  }
});

// -------------- Get current user's profile -------------- CHECKED, WORKS!

app.get("/user/profile", authenticateToken, async (req, res) => {
  // console.log("HIT /user/profile", new Date().toISOString());
  console.log("req.user:", req.user.uid);
  //This has now been properly protected with Firebase token authentication.

  // at this point, the user will have to be logged in so no need for checking if user exists.

  try {
    const user_id = req.user.uid; // From Firebase token via middleware
    const client = await pool.connect();
    // Query using Firebase User ID, not internal database user ID
    const result = await client.query(
      "SELECT * FROM users WHERE user_id = $1",
      [user_id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: "User not found" });
    }
    res.json({ details: result.rows[0] });
    client.release();
  } catch (err) {
    res
      .status(400)
      .json({ error: "Something went wrong, please try again later" });
  }
});

// -------------- Get user and deal details from the username --------------

app.get("/user/:username", async (req, res) => {
  const { username } = req.params;
  const client = await pool.connect();
  try {
    // Get user details
    const userResult = await client.query(
      "SELECT user_id, username, profile_pic, created_at FROM users WHERE username = $1",
      [username]
    );

    if (userResult.rows.length === 0) {
      return res.status(404).json({ error: "User not found" });
    }

    const userDetails = userResult.rows[0];

    // Get deals created by this user
    const dealsResult = await client.query(
      "SELECT * FROM deal WHERE user_id = $1 AND is_active = true",
      [userDetails.user_id]
    );

    res.json({
      user: userDetails,
      deals: dealsResult.rows,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Database error" });
  } finally {
    client.release();
  }
});

// -------------- Testing 1 --------------

app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} - ${req.method} ${req.path}`);
  console.log("Headers:", req.headers);
  next();
});

// -------------- Testing 2 --------------

app.get("/test-route", (req, res) => {
  res.json({
    message: "Route is working!",
    timestamp: new Date().toISOString(),
  });
});

// -------------- Update user profile -------------- CHECKED, WORKS!

app.put("/user/edit", authenticateToken, async (req, res) => {
  const { username, profile_pic, updated_at } = req.body;
  // The user is now authenticated via the middleware
  const client = await pool.connect();

  try {
    console.log(req, req.user);
    const user_id = req.user.uid; // From Firebase token
    const userDetails = await client.query(
      "UPDATE users SET username = $1, profile_pic = $2, updated_at = CURRENT_TIMESTAMP WHERE user_id = $3 RETURNING *",
      [username, profile_pic, user_id]
    );
    console.log(userDetails);
    if (userDetails.rows.length === 0) {
      // Perhaps the user does not exist (user ID not matching)
      res.status(400).json({ error: "Could not find the User" });
    } else {
      // User updated successfully
      res.json(userDetails.rows[0]);
    }
  } catch (err) {
    console.log(err.stack);
    res
      .status(500)
      .json({ error: "Something went wrong, please try again later!" });
  } finally {
    client.release();
  }
});

// 2. CATEGORIES ENDPOINTS

// -------------- Get all active categories -------------- CHECKED, WORKS!

app.get("/categories", async (req, res) => {
  const { categories } = req.params;
  const client = await pool.connect();
  try {
    const listCategories = await client.query(
      "SELECT category_name FROM categories"
    );

    if (listCategories.rows.length === 0) {
      // if there are no categories in the table:
      res.status(400).json({
        error: "Could not find any categories. Please add some and try again.",
      });
    } else {
      // Return the list of categories.
      res.json(listCategories.rows);
    }
  } catch (err) {
    console.log(err.stack);
    res
      .status(500)
      .json({ error: "something went wrong, please try again later! " });
  } finally {
    client.release();
  }
});

// -------------- Create new category -------------- CHECKED, WORKS!

app.post("/categories", authenticateToken, isAdmin, async (req, res) => {
  const { category_name } = req.body;
  const client = await pool.connect();

  try {
    const newCategory = await client.query(
      "INSERT INTO categories (category_name) VALUES ($1) RETURNING *",
      [category_name]
    );
    res.json(newCategory.rows[0]); // Return the newly created category
  } catch (err) {
    console.log(err.stack);
    res
      .status(500)
      .json({ error: "Something went wrong, please try again later!" });
  } finally {
    client.release();
  }
});

// -------------- Delete a category -------------- CHECKED, WORKS!

app.delete("/categories", authenticateToken, isAdmin, async (req, res) => {
  const { category_name } = req.body;
  const client = await pool.connect();

  try {
    const deleteCategory = await client.query(
      "DELETE FROM categories WHERE category_name = $1 RETURNING *",
      [category_name]
    );
    res.json(
      {
        message: `The Category "${category_name}" has been successfully deleted`,
      },
      deleteCategory.rows
    ); // Return the updated category list
  } catch (err) {
    console.log(err.stack);
    res
      .status(500)
      .json({ error: "Something went wrong, please try again later!" });
  } finally {
    client.release();
  }
});

// 3. DEALS ENDPOINTS (Core functionality)

// -------------- Get all the active deals -------------- CHECKED, WORKS!

app.get("/deals", tryAuthenticateToken, async (req, res) => {
  const client = await pool.connect();
  try {
    const user_id = req.user ? req.user.uid : null; // Get the user ID from the authenticated user, or null if not authenticated

    let listDeals = await client.query(
      `SELECT d.*, 
         di.image_url as primary_image_url,
         u.username,
         u.profile_pic
       FROM deal d
       LEFT JOIN deal_images di ON d.deal_id = di.deal_id AND di.is_primary_pic = true
       LEFT JOIN users u ON d.user_id = u.user_id
       WHERE d.is_active = true`
    );

    if (listDeals.rows.length === 0) {
      return res.status(400).json({
        error: "Could not find any deals. Please add some and try again.",
      });
    } else {
      const dealsWithVotes = await Promise.all(
        listDeals.rows.map(async (deal) => {
          // Get upvotes, downvotes, net votes
          const upvoteResult = await client.query(
            "SELECT COUNT(*) FROM votes WHERE deal_id = $1 AND vote_type = 'up'",
            [deal.deal_id]
          );
          const downvoteResult = await client.query(
            "SELECT COUNT(*) FROM votes WHERE deal_id = $1 AND vote_type = 'down'",
            [deal.deal_id]
          );
          const upvoteCount = parseInt(upvoteResult.rows[0].count);
          const downvoteCount = parseInt(downvoteResult.rows[0].count);
          const netVotes = upvoteCount - downvoteCount;

          // Get the current user's vote for this deal
          let userVote = null;
          if (user_id) {
            const userVoteResult = await client.query(
              "SELECT vote_type FROM votes WHERE deal_id = $1 AND user_id = $2 LIMIT 1",
              [deal.deal_id, user_id]
            );
            if (userVoteResult.rows.length > 0) {
              userVote = userVoteResult.rows[0].vote_type;
            }
          }

          return {
            ...deal,
            up_votes: upvoteCount,
            down_votes: downvoteCount,
            net_votes: netVotes,
            user_vote: userVote, // <-- Add this
          };
        })
      );

      res.json(dealsWithVotes);
    }
  } catch (err) {
    console.log(err.stack);
    res
      .status(500)
      .json({ error: "Something went wrong, please try again later!" });
  } finally {
    client.release();
  }
});

// -------------- Get single deal with full details -------------- CHECKED, WORKS!

app.get("/deals/:deal_id", async (req, res) => {
  const { deal_id } = req.params;
  const client = await pool.connect();
  try {
    const dealDetails = await client.query(
      "SELECT * FROM deal WHERE deal_id = $1 AND is_active = true",
      [deal_id]
    );

    if (dealDetails.rows.length === 0) {
      // if there are no deals in the table:
      res.status(400).json({
        error: "Could not find any deals with that ID. Please try again.",
      });
    } else {
      // Return the list of deals.
      res.json(dealDetails.rows[0]);
    }
  } catch (err) {
    console.log(err.stack);
    res
      .status(500)
      .json({ error: "Something went wrong, please try again later!" });
  } finally {
    client.release();
  }
});

// Get full deal details including all images and category info

app.get("/deals/:deal_id/full", async (req, res) => {
  const { deal_id } = req.params;
  const client = await pool.connect();
  try {
    // Get deal info with user info
    const dealResult = await client.query(
      `SELECT d.*, u.username, u.profile_pic, c.category_name
FROM deal d
LEFT JOIN users u ON d.user_id = u.user_id
LEFT JOIN categories c ON d.category_id = c.category_id
WHERE d.deal_id = $1 AND d.is_active = true`,
      [deal_id]
    );
    if (dealResult.rows.length === 0) {
      return res.status(404).json({ error: "Deal not found" });
    }

    // Get all images for this deal
    const imagesResult = await client.query(
      "SELECT * FROM deal_images WHERE deal_id = $1 ORDER BY display_order ASC",
      [deal_id]
    );

    // Return deal info and images
    res.json({
      ...dealResult.rows[0],
      images: imagesResult.rows,
    });
  } catch (err) {
    console.log(err.stack);
    res
      .status(500)
      .json({ error: "Something went wrong, please try again later!" });
  } finally {
    client.release();
  }
});

// -------------- Get all images for this deal --------------

app.get("/deals/:deal_id/images", async (req, res) => {
  const { deal_id } = req.params;
  const client = await pool.connect();

  try {
    const images = await client.query(
      "SELECT * FROM deal_images WHERE deal_id = $1 ORDER BY display_order ASC",
      [deal_id]
    );

    if (images.rows.length === 0) {
      return res.status(404).json({ error: "No images found for this deal" });
    }

    res.json(images.rows);
  } catch (error) {
    console.error("Get images error:", error);
    res.status(500).json({ error: "Failed to retrieve images" });
  } finally {
    client.release();
  }
});

// -------------- Create a new deal -------------- CHECKED, WORKS!

app.post("/deals", authenticateToken, async (req, res) => {
  const user_id = req.user.uid; // Get the user ID from the authenticated user
  const {
    title,
    description,
    category_name, // Selected from a dropdown in the frontend
    price,
    original_price,
    deal_url,
    image_url,
  } = req.body;
  const client = await pool.connect();

  try {
    // first , get the category ID from the category name
    const categoryResult = await client.query(
      "SELECT category_id FROM categories WHERE category_name = $1",
      [category_name]
    );

    if (categoryResult.rows.length === 0) {
      return res.status(400).json({
        error: "Category does not exist. Please select a valid category.",
      });
    }

    const category_id = categoryResult.rows[0].category_id; // Get the category ID from the result

    // Check if the deal already exists
    const existingDeal = await client.query(
      "SELECT * FROM deal WHERE deal_url = $1",
      [deal_url]
    );
    if (existingDeal.rows.length > 0) {
      return res.status(400).json({
        error: "This deal already exists. Cannot create a duplicate deal.",
      });
    } else {
      // Deal does not exist, proceed to create a new deal
      const newDeal = await client.query(
        "INSERT INTO deal (title, description, category_id, price, original_price, deal_url, image_url, created_at, user_id) VALUES ($1, $2, $3, $4, $5, $6, $7, CURRENT_TIMESTAMP, $8) RETURNING *",
        [
          title,
          description,
          category_id, // This should be the ID of the category, not the name
          price,
          original_price,
          deal_url,
          image_url,
          user_id,
        ]
      );
      res.json(newDeal.rows[0]); // Return the newly created deal
    }
  } catch (err) {
    console.log(err.stack);
    res
      .status(500)
      .json({ error: "Something went wrong, please try again later!" });
  } finally {
    client.release();
  }
});

// -------------- Update a deal -------------- CHECKED, WORKS!

app.put("/deals/:deal_id", authenticateToken, async (req, res) => {
  const { deal_id } = req.params; // Get the deal ID from the URL parameters
  const user_id = req.user.uid; // Get the user ID from the authenticated user
  const client = await pool.connect();

  const check_user = await pool.query(
    "SELECT user_id FROM deal WHERE deal_id = $1",
    [deal_id]
  );
  try {
    if (check_user.rows.length === 0) {
      return res.status(404).json({ error: "Deal not found" });
    }
    if (check_user.rows[0].user_id !== user_id && !isAdmin) {
      return res
        .status(403)
        .json({ error: "You are not authorized to edit this deal" });
    } else {
      const {
        title,
        description,
        category_name, // Selected from a dropdown in the frontend
        price,
        original_price,
        deal_url,
        image_url,
        updated_at,
      } = req.body;
      const client = await pool.connect();

      // first , get the category ID from the category name
      const categoryResult = await client.query(
        "SELECT category_id FROM categories WHERE category_name = $1",
        [category_name]
      );

      if (categoryResult.rows.length === 0) {
        return res.status(400).json({
          error: "Category does not exist. Please select a valid category.",
        });
      }

      const category_id = categoryResult.rows[0].category_id; // Get the category ID from the result

      // Update the deal
      const updatedDeal = await client.query(
        "UPDATE deal SET title = $1, description = $2, category_id = $3, price = $4, original_price = $5, deal_url = $6, image_url = $7, updated_at = CURRENT_TIMESTAMP WHERE deal_id = $8 RETURNING *",
        [
          title,
          description,
          category_id, // This should be the ID of the category, not the name.
          price,
          original_price,
          deal_url,
          image_url,
          deal_id,
        ]
      );
      console.log(updatedDeal);

      if (updatedDeal.rows.length === 0) {
        return res.status(404).json({ error: "Deal not found or not updated" });
      } else {
        // Deal updated successfully

        res.json(updatedDeal.rows[0]); // Return the updated deal
      }
    }
  } catch (err) {
    console.log(err.stack);
    res
      .status(500)
      .json({ error: "Something went wrong, please try again later!" });
  } finally {
    client.release();
  }
});

// -------------- Soft delete deal (set is_active = false) -------------- CHECKED, WORKS!

app.delete("/deals/:deal_id", authenticateToken, async (req, res) => {
  const { deal_id } = req.params;
  const user_id = req.user.uid;
  const client = await pool.connect();

  try {
    // Check if the deal exists and get deal info
    const check_user = await client.query(
      "SELECT * FROM deal WHERE deal_id = $1",
      [deal_id]
    );

    if (check_user.rows.length === 0) {
      return res.status(404).json({ error: "Deal not found" });
    }

    // Check if user is admin
    const adminCheck = await client.query(
      "SELECT is_admin FROM users WHERE user_id = $1",
      [user_id]
    );

    const isAdmin = adminCheck.rows.length > 0 && adminCheck.rows[0].is_admin;

    // Now you can use isAdmin safely
    if (check_user.rows[0].user_id !== user_id && !isAdmin) {
      return res.status(403).json({
        error: "You are not authorized to remove this deal",
      });
    }

    if (!check_user.rows[0].is_active) {
      return res.status(400).json({ error: "Deal is already inactive" });
    }

    // Soft delete the deal
    const softDeleteDeal = await client.query(
      "UPDATE deal SET is_active = false, updated_at = CURRENT_TIMESTAMP WHERE deal_id = $1 RETURNING *",
      [deal_id]
    );

    if (softDeleteDeal.rows.length === 0) {
      return res.status(404).json({ error: "Deal not found or removed" });
    }

    res.json({
      message: `The deal with ID ${deal_id} has been successfully removed`,
      deal: softDeleteDeal.rows[0],
    });
  } catch (err) {
    console.log(err.stack);
    res
      .status(500)
      .json({ error: "Something went wrong, please try again later!" });
  } finally {
    client.release();
  }
});

// -------------- Reactivate a soft-deleted deal --------------

app.put("/deals/:deal_id/reactivate", authenticateToken, async (req, res) => {
  const { deal_id } = req.params;
  const user_id = req.user.uid;
  const client = await pool.connect();

  try {
    // Check if the deal exists
    const dealResult = await client.query(
      "SELECT * FROM deal WHERE deal_id = $1",
      [deal_id]
    );

    if (dealResult.rows.length === 0) {
      return res.status(404).json({ error: "Deal not found" });
    }

    // Check if user is admin
    const adminCheck = await client.query(
      "SELECT is_admin FROM users WHERE user_id = $1",
      [user_id]
    );

    const isAdmin = adminCheck.rows.length > 0 && adminCheck.rows[0].is_admin;
    const isOwner = dealResult.rows[0].user_id === user_id;

    // Only the owner or an admin can reactivate
    if (!isOwner && !isAdmin) {
      return res.status(403).json({
        error: "You are not authorized to reactivate this deal",
      });
    }

    // Check if deal is already active
    if (dealResult.rows[0].is_active) {
      return res.status(400).json({ error: "Deal is already active" });
    }

    // Reactivate the deal
    const reactivateResult = await client.query(
      "UPDATE deal SET is_active = true, updated_at = CURRENT_TIMESTAMP WHERE deal_id = $1 RETURNING *",
      [deal_id]
    );

    res.json({
      message: `The deal with ID ${deal_id} has been reactivated`,
      deal: reactivateResult.rows[0],
    });
  } catch (err) {
    console.log(err.stack);
    res
      .status(500)
      .json({ error: "Something went wrong, please try again later!" });
  } finally {
    client.release();
  }
});

// -------------- Get deals by specific user -------------- CHECKED, WORKS!

app.get("/deals/user/:user_id", async (req, res) => {
  const { user_id } = req.params; // Get the user ID from the URL parameters
  const client = await pool.connect();

  try {
    // Check if the user exists
    const userExists = await client.query(
      "SELECT * FROM users WHERE user_id = $1",
      [user_id]
    );

    if (userExists.rows.length === 0) {
      return res.status(404).json({ error: "User not found" });
    }

    // Get deals created by the specific user
    const userDeals = await client.query(
      "SELECT * FROM deal WHERE user_id = $1 AND is_active = true",
      [user_id]
    );

    if (userDeals.rows.length === 0) {
      return res.status(404).json({ error: "No deals found for this user" });
    }

    res.json(userDeals.rows); // Return the user's deals
  } catch (err) {
    console.log(err.stack);
    res
      .status(500)
      .json({ error: "Something went wrong, please try again later!" });
  } finally {
    client.release();
  }
});

// -------------- Get all categories with their associated deals --------------

app.get("/categories-with-deals", async (req, res) => {
  const client = await pool.connect();
  try {
    // Get all categories
    const categoriesResult = await client.query(
      "SELECT category_id, category_name FROM categories"
    );
    const categories = categoriesResult.rows;

    // Get all active deals with their category_id
    const dealsResult = await client.query(
      `SELECT d.*, 
              di.image_url as primary_image_url,
              u.username,
              u.profile_pic,
              c.category_name
         FROM deal d
         LEFT JOIN deal_images di ON d.deal_id = di.deal_id AND di.is_primary_pic = true
         LEFT JOIN users u ON d.user_id = u.user_id
         LEFT JOIN categories c ON d.category_id = c.category_id
         WHERE d.is_active = true`
    );
    const deals = dealsResult.rows;

    // Map deals to their categories
    const categoriesWithDeals = categories.map((cat) => ({
      ...cat,
      deals: deals.filter((deal) => deal.category_id === cat.category_id),
    }));

    res.json(categoriesWithDeals);
  } catch (err) {
    console.log(err.stack);
    res
      .status(500)
      .json({ error: "Something went wrong, please try again later!" });
  } finally {
    client.release();
  }
});

// 4. VOTING ENDPOINTS

// -------------- Vote a deal (up/down)-------------- CHECKED, WORKS! - Duplicaate to the remove vote endpoint

// app.post("/deals/vote", authenticateToken, async (req, res) => {
//   const { deal_id, vote_type } = req.body; // Expecting 'up' or 'down' for vote_type
//   const user_id = req.user.uid; // Get the user ID from the authenticated user
//   // Convert deal_id to integer (in case it comes in as a string like "1")
//   // const deal_id_int = parseInt(deal_id, 10);

//   const client = await pool.connect();

//   try {
//     // Check if the deal exists
//     const dealExists = await client.query(
//       "SELECT * FROM deal WHERE deal_id = $1 AND is_active = true",
//       [deal_id_int]
//     );

//     if (dealExists.rows.length === 0) {
//       return res.status(404).json({ error: "Deal not found or inactive" });
//     }

//     // Check if the user has already voted on this deal.
//     const existingVote = await client.query(
//       "SELECT * FROM votes WHERE user_id = $1 AND deal_id = $2",
//       [user_id, deal_id_int]
//     );

//     if (existingVote.rows.length > 0) {
//       // User has already voted, update the vote type
//       const updatedVote = await client.query(
//         "UPDATE votes SET vote_type = $1 WHERE user_id = $2 AND deal_id = $3 RETURNING *",
//         [vote_type, user_id, deal_id_int]
//       );
//       res.json(updatedVote.rows[0]); // Return the updated vote
//     } else {
//       // User has not voted yet, insert a new vote
//       const newVote = await client.query(
//         "INSERT INTO votes (user_id, deal_id, vote_type) VALUES ($1, $2, $3) RETURNING *",
//         [user_id, deal_id_int, vote_type]
//       );
//       res.json(newVote.rows[0]); // Return the new vote
//     }
//   } catch (err) {
//     console.log(err.stack);
//     res
//       .status(500)
//       .json({ error: "Something went wrong, please try again later!" });
//   } finally {
//     client.release();
//   }
// });

// -------------- Add or Remove vote -------------- CHECKED, WORKS!

app.put("/deals/addremove/vote", authenticateToken, async (req, res) => {
  console.log("Vote endpoint hit");
  const { deal_id, vote_type } = req.body; // vote_type should be 'up' or 'down'
  const user_id = String(req.user.uid);
  // const deal_id = parseInt(deal_id, 10); // Convert to integer

  console.log(
    "Toggle vote - deal_id:",
    deal_id,
    "vote_type:",
    vote_type,
    "user_id:",
    user_id
  );

  const client = await pool.connect();

  try {
    // First check if the deal exists
    const dealExists = await client.query(
      "SELECT * FROM deal WHERE deal_id = $1 AND is_active = true",
      [deal_id]
    );

    if (dealExists.rows.length === 0) {
      return res.status(404).json({ error: "Deal not found or inactive" });
    }

    // Check if user has already voted on this deal
    const existingVote = await client.query(
      "SELECT * FROM votes WHERE user_id = $1 AND deal_id = $2",
      [user_id, deal_id]
    );

    if (existingVote.rows.length > 0) {
      const currentVoteType = existingVote.rows[0].vote_type;

      if (currentVoteType === vote_type) {
        // Same vote type - REMOVE the vote (toggle off)
        await client.query(
          "DELETE FROM votes WHERE user_id = $1 AND deal_id = $2",
          [user_id, deal_id]
        );
        return res.json({
          message: "Vote removed",
          action: "removed",
          vote_type: vote_type,
        });
      } else {
        // Different vote type - UPDATE to new vote type
        const updatedVote = await client.query(
          "UPDATE votes SET vote_type = $1, updated_at = CURRENT_TIMESTAMP WHERE user_id = $2 AND deal_id = $3 RETURNING *",
          [vote_type, user_id, deal_id]
        );
        return res.json({
          message: "Vote updated",
          action: "updated",
          vote: updatedVote.rows[0],
        });
      }
    } else {
      // No existing vote - CREATE new vote
      const newVote = await client.query(
        "INSERT INTO votes (user_id, deal_id, vote_type) VALUES ($1, $2, $3) RETURNING *",
        [user_id, deal_id, vote_type]
      );
      return res.json({
        message: "Vote added",
        action: "added",
        vote: newVote.rows[0],
      });
    }
  } catch (err) {
    console.error("Vote toggle error:", err);
    res.status(500).json({ error: "Something went wrong" });
  } finally {
    client.release();
  }
});
// 5. DEAL IMAGES ENDPOINTS

// -------------- Upload and update user profile picture --------------
app.post(
  "/user/profile-pic",
  authenticateToken,
  upload.single("profile_pic"),
  async (req, res) => {
    const user_id = req.user.uid;

    if (!req.file) {
      return res.status(400).json({ error: "No image file provided" });
    }

    const client = await pool.connect();

    try {
      // Optional: Get the current profile_pic URL to delete the old image from Cloudinary
      const userResult = await client.query(
        "SELECT profile_pic FROM users WHERE user_id = $1",
        [user_id]
      );
      const oldPicUrl = userResult.rows[0]?.profile_pic;

      // Upload new image to Cloudinary (profile folder)
      const uploadResult = await uploadToCloudinary(req.file.buffer, "profile");

      // Update user's profile_pic in the database
      const updateResult = await client.query(
        "UPDATE users SET profile_pic = $1, updated_at = CURRENT_TIMESTAMP WHERE user_id = $2 RETURNING profile_pic",
        [uploadResult.secure_url, user_id]
      );

      // Delete old image from Cloudinary if it exists and is in the 'profile' folder
      if (oldPicUrl && oldPicUrl.includes("/profile/")) {
        const urlParts = oldPicUrl.split("/");
        const publicIdWithExt = urlParts[urlParts.length - 1];
        const publicId = publicIdWithExt.split(".")[0];
        const folderPublicId = `profile/${publicId}`;
        try {
          await cloudinary.uploader.destroy(folderPublicId);
        } catch (cloudinaryError) {
          console.error("Cloudinary deletion error:", cloudinaryError);
        }
      }

      res.json({
        message: "Profile picture updated successfully",
        profile_pic: uploadResult.secure_url,
      });
    } catch (error) {
      console.error("Profile pic upload error:", error);
      res.status(500).json({ error: "Failed to update profile picture" });
    } finally {
      client.release();
    }
  }
);

// -------------- Upload single image for a deal --------------
app.post(
  "/deals/:deal_id/images",
  authenticateToken,
  upload.single("image"),
  async (req, res) => {
    const { deal_id } = req.params;
    const user_id = req.user.uid;
    const { is_primary_pic = false } = req.body;

    if (!req.file) {
      return res.status(400).json({ error: "No image file provided" });
    }

    const client = await pool.connect();

    try {
      // Check if the deal exists and belongs to the user
      const dealCheck = await client.query(
        "SELECT * FROM deal WHERE deal_id = $1 AND user_id = $2 AND is_active = true",
        [deal_id, user_id]
      );

      if (dealCheck.rows.length === 0) {
        return res.status(404).json({
          error: "Deal not found or you do not have permission to add images",
        });
      }

      // Upload image to Cloudinary
      const uploadResult = await uploadToCloudinary(req.file.buffer, "deals");

      // Get the next display order
      const orderResult = await client.query(
        "SELECT COALESCE(MAX(display_order), 0) + 1 as next_order FROM deal_images WHERE deal_id = $1",
        [deal_id]
      );
      const displayOrder = orderResult.rows[0].next_order;

      // If this is set as primary, update other images to not be primary
      if (is_primary_pic === true || is_primary_pic === "true") {
        await client.query(
          "UPDATE deal_images SET is_primary_pic = false WHERE deal_id = $1",
          [deal_id]
        );
      }

      // Save image info to database
      const newImage = await client.query(
        "INSERT INTO deal_images (deal_id, image_url, is_primary_pic, display_order) VALUES ($1, $2, $3, $4) RETURNING *",
        [deal_id, uploadResult.secure_url, is_primary_pic, displayOrder]
      );

      res.json({
        message: "Image uploaded successfully",
        image: newImage.rows[0],
        cloudinary_data: {
          public_id: uploadResult.public_id,
          secure_url: uploadResult.secure_url,
        },
      });
    } catch (error) {
      console.error("Image upload error:", error);
      res.status(500).json({ error: "Failed to upload image" });
    } finally {
      client.release();
    }
  }
);

// -------------- Upload multiple images for a deal --------------
app.post(
  "/deals/:deal_id/images/multiple",
  authenticateToken,
  upload.array("images", 5), // Limit to 5 images
  async (req, res) => {
    const { deal_id } = req.params;
    const user_id = req.user.uid;

    if (!req.files || req.files.length === 0) {
      return res.status(400).json({ error: "No image files provided" });
    }

    const client = await pool.connect();

    try {
      // Check if the deal exists and belongs to the user
      const dealCheck = await client.query(
        "SELECT * FROM deal WHERE deal_id = $1 AND user_id = $2 AND is_active = true",
        [deal_id, user_id]
      );

      if (dealCheck.rows.length === 0) {
        return res.status(404).json({
          error: "Deal not found or you do not have permission to add images",
        });
      }

      // Get the next display order
      const orderResult = await client.query(
        "SELECT COALESCE(MAX(display_order), 0) as max_order FROM deal_images WHERE deal_id = $1",
        [deal_id]
      );
      let nextOrder = orderResult.rows[0].max_order + 1;

      const uploadedImages = [];

      // Upload each image to Cloudinary and save to database
      for (const file of req.files) {
        try {
          const uploadResult = await uploadToCloudinary(file.buffer, "deals");

          const newImage = await client.query(
            "INSERT INTO deal_images (deal_id, image_url, is_primary_pic, display_order) VALUES ($1, $2, $3, $4) RETURNING *",
            [deal_id, uploadResult.secure_url, false, nextOrder]
          );

          uploadedImages.push({
            image: newImage.rows[0],
            cloudinary_public_id: uploadResult.public_id,
          });

          nextOrder++;
        } catch (uploadError) {
          console.error("Error uploading individual image:", uploadError);
          // Continue with other images even if one fails
        }
      }

      res.json({
        message: `Successfully uploaded ${uploadedImages.length} images`,
        images: uploadedImages,
      });
    } catch (error) {
      console.error("Multiple image upload error:", error);
      res.status(500).json({ error: "Failed to upload images" });
    } finally {
      client.release();
    }
  }
);

// -------------- Get all images for a deal --------------
app.get("/deals/:deal_id/images", async (req, res) => {
  const { deal_id } = req.params;
  const client = await pool.connect();

  try {
    const images = await client.query(
      "SELECT * FROM deal_images WHERE deal_id = $1 ORDER BY display_order ASC",
      [deal_id]
    );

    if (images.rows.length === 0) {
      return res.status(404).json({ error: "No images found for this deal" });
    }

    res.json(images.rows);
  } catch (error) {
    console.error("Get images error:", error);
    res.status(500).json({ error: "Failed to retrieve images" });
  } finally {
    client.release();
  }
});

// -------------- Delete an image --------------
app.delete(
  "/deals/:deal_id/images/:image_id",
  authenticateToken,
  async (req, res) => {
    const { deal_id, image_id } = req.params;
    const user_id = req.user.uid;

    const client = await pool.connect();

    try {
      // Check if the deal belongs to the user
      const dealCheck = await client.query(
        "SELECT * FROM deal WHERE deal_id = $1 AND user_id = $2",
        [deal_id, user_id]
      );

      if (dealCheck.rows.length === 0) {
        return res
          .status(404)
          .json({ error: "Deal not found or you do not have permission" });
      }

      // Get image info before deleting
      const imageResult = await client.query(
        "SELECT * FROM deal_images WHERE image_id = $1 AND deal_id = $2",
        [image_id, deal_id]
      );

      if (imageResult.rows.length === 0) {
        return res.status(404).json({ error: "Image not found" });
      }

      const image = imageResult.rows[0];

      // Extract public_id from Cloudinary URL to delete from Cloudinary
      const urlParts = image.image_url.split("/");
      const publicIdWithExtension = urlParts[urlParts.length - 1];
      const publicId = publicIdWithExtension.split(".")[0];
      const folderPublicId = `deals/${publicId}`;

      try {
        // Delete from Cloudinary
        await cloudinary.uploader.destroy(folderPublicId);
      } catch (cloudinaryError) {
        console.error("Cloudinary deletion error:", cloudinaryError);
        // Continue with database deletion even if Cloudinary deletion fails
      }

      // Delete from database
      const deletedImage = await client.query(
        "DELETE FROM deal_images WHERE image_id = $1 AND deal_id = $2 RETURNING *",
        [image_id, deal_id]
      );

      res.json({
        message: "Image deleted successfully",
        deleted_image: deletedImage.rows[0],
      });
    } catch (error) {
      console.error("Delete image error:", error);
      res.status(500).json({ error: "Failed to delete image" });
    } finally {
      client.release();
    }
  }
);

// -------------- Set primary image -------------- CHECKED, WORKS!
app.put(
  "/deals/:deal_id/images/:image_id/primary",
  authenticateToken,
  async (req, res) => {
    const { deal_id, image_id } = req.params;
    const user_id = req.user.uid;

    const client = await pool.connect();

    try {
      // Check if the deal belongs to the user
      const dealCheck = await client.query(
        "SELECT * FROM deal WHERE deal_id = $1 AND user_id = $2",
        [deal_id, user_id]
      );

      if (dealCheck.rows.length === 0) {
        return res
          .status(404)
          .json({ error: "Deal not found or you do not have permission" });
      }

      // First, set all images for this deal to not primary
      await client.query(
        "UPDATE deal_images SET is_primary_pic = false WHERE deal_id = $1",
        [deal_id]
      );

      // Then set the selected image as primary
      const updatedImage = await client.query(
        "UPDATE deal_images SET is_primary_pic = true WHERE image_id = $1 AND deal_id = $2 RETURNING *",
        [image_id, deal_id]
      );

      if (updatedImage.rows.length === 0) {
        return res.status(404).json({ error: "Image not found" });
      }

      res.json({
        message: "Primary image updated successfully",
        image: updatedImage.rows[0],
      });
    } catch (error) {
      console.error("Set primary image error:", error);
      res.status(500).json({ error: "Failed to set primary image" });
    } finally {
      client.release();
    }
  }
);

// ------------ WELCOME MESSAGE WHEN THE API RUNS --------------
app.get("/", (req, res) => {
  res.json({ message: "Welcome to Shah's deal page. ver 7" });
});
// ----------- TELLS EXPRESS TO START THE SERVER AND LISTEN FOR REQUESTS -----------

app.listen(3000, () => {
  console.log("App is listening on port 3000");
});
