import express from "express";
import { authenticator } from "otplib";
import qrcode from 'qrcode';

const app = express();
const PORT = 8000;

// Middleware to parse JSON request bodies
app.use(express.json());

// Serve static files from the 'public' directory
app.use(express.static('public'))

// In-memory store for user secrets
const secrets = {}

// Endpoint to enable 2FA for a user
app.post("/enable2FA", async (req, res) => {
  // Generate a unique secret for the user
  const secret = authenticator.generateSecret();
  
  // Extract the user's email from the request body
  const { email } = req.body;
  
  // Store the secret in memory associated with the user's email
  secrets[email] = secret;
  console.log(secret);  // Log the secret for debugging purposes
  
  // Generate a URI for the OTP authentication
  const otp = authenticator.keyuri(email, "2FA App", secret);
  
  // Generate a QR code image from the URI and encode it as a Data URL
  const imageUrl = await qrcode.toDataURL(otp);
  
  // Respond with the QR code image URL
  return res.json({ imageUrl });
});

// Endpoint to verify the OTP entered by the user
app.post("/verify", async (req, res) => {
  // Extract the user's email and OTP from the request body
  const { email, otp } = req.body;
  
  // Retrieve the secret associated with the user's email
  const secret = secrets[email];
  
  // If no secret is found, return a 404 error
  if (!secret) {
    return res.status(404).json({ error: "Email not registered" });
  }
  
  // Check if the provided OTP is valid using the stored secret
  const isValid = authenticator.check(otp, secret);
  
  // Respond with the validation result
  return res.json({ isValid });
})

// Start the server and listen on the specified port
app.listen(PORT, () => {
  console.log(`Listening on ${PORT}`);
})
