// // /api/user/profile.js
// import admin from "../../lib/firebaseAdmin"; // Adjust path if needed
// import { Pool } from "pg";

// const pool = new Pool({
//   connectionString: process.env.DATABASE_URL,
//   ssl: { rejectUnauthorized: false },
// });

// export default async function handler(req, res) {
//   if (req.method !== "GET") {
//     return res.status(405).json({ error: "Method not allowed" });
//   }
//   try {
//     const authHeader = req.headers["authorization"];
//     if (!authHeader)
//       return res.status(401).json({ error: "Access token required" });
//     const token = authHeader.split(" ")[1];
//     const decodedToken = await admin.auth().verifyIdToken(token);
//     const user_id = decodedToken.uid;
//     const client = await pool.connect();
//     try {
//       const result = await client.query(
//         "SELECT * FROM users WHERE user_id = $1",
//         [user_id]
//       );
//       if (result.rows.length === 0) {
//         return res.status(404).json({ error: "User not found" });
//       }
//       res.json({ details: result.rows[0] });
//     } finally {
//       client.release();
//     }
//   } catch (err) {
//     console.error(err);
//     res
//       .status(400)
//       .json({ error: "Something went wrong, please try again later" });
//   }
// }
