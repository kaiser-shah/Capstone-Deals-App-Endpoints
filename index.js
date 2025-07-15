// Importing the required libraries
const express = require("express"); // Express framework for building the server
let path = require("path"); // Path module for handling file paths
const cors = require("cors"); // CORS module for handling cross-origin requests (important for frontend-backend communication))
require("dotenv").config(); // Dotenv module for loading environment variables from a .env file

// const bcrypt = require("bcrypt"); // Bcrypt module for hashing passwords
// const jwt = require("jsonwebtoken"); // JWT module for handling JSON Web Tokens (important for authentication)

// Postgres client setup
const { Pool } = require("pg"); // Importing the Pool class from the pg module
const { DATABASE_URL, SECRET_KEY } = process.env; // Loading the database URL and secret key from the environment variables

// Initialise the express app
let app = express();

//Middleware Setup
app.use(cors()); // Enable CORS for all routes
app.use(express.json()); // Enables JSON parsing into req.body

// Setup connection pool for postgreSQL
const pool = new Pool({
  connectionString: DATABASE_URL, // Use the DATABASE_URL environment variable for the connection string
  ssl: {
    rejectUnauthorized: false, // Disable SSL certificate verification (for local development only)
  },
});

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

// upload a deal
// picture, description, price, location, category, user_id.

// ------------ WELCOME MESSAGE WHEN THE API RUNS --------------
app.get("/", (req, res) => {
  res.json({ message: "Welcome to Shah's deal page. ver 7" });
});
// ----------- TELLS EXPRESS TO START THE SERVER AND LISTEN FOR REQUESTS -----------

app.listen(3000, () => {
  console.log("App is listening on port 3000");
});
