require("dotenv").config();

const express = require("express");
const { requestOtp, verifyOtp } = require("./otp");
const { sendOtpEmail } = require("./email");

const app = express();

app.use(express.json());

const PORT = process.env.PORT || 3000;

function isValidEmail(email) {
  return typeof email === "string" && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

app.get("/health", (req, res) => {
  res.json({
    status: "ok"
  });
});

async function sendOtp(req, res) {
  const { email } = req.body || {};

  if (!isValidEmail(email)) {
    return res.status(400).json({
      success: false,
      error: "A valid email is required"
    });
  }

  const result = requestOtp(email);

  if (!result.success) {
    return res.status(429).json(result);
  }

  try {
    await sendOtpEmail(email, result.otp);
  } catch (error) {
    return res.status(502).json({
      success: false,
      error: "Unable to send OTP email"
    });
  }

  return res.status(202).json({
    success: true,
    message: "OTP sent"
  });
}

function verifyOtpCode(req, res) {
  const { email, otp } = req.body || {};

  if (!isValidEmail(email) || typeof otp !== "string" || !/^\d{6}$/.test(otp)) {
    return res.status(400).json({
      success: false,
      error: "A valid email and six-digit OTP are required"
    });
  }

  const result = verifyOtp(email, otp);

  if (!result.success) {
    return res.status(400).json(result);
  }

  return res.json(result);
}

app.post("/send-otp", sendOtp);
app.post("/otp/request", sendOtp);
app.post("/verify-otp", verifyOtpCode);
app.post("/otp/verify", verifyOtpCode);

if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`OTP system running on http://localhost:${PORT}`);
  });
}

module.exports = app;