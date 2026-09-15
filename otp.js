// using crypto module to generate a random OTP instead of Math.random() for better security
const crypto = require('crypto');


// users Map to store OTP data for each email
const users = new Map();

const MAX_REQUESTS_PER_HOUR = Number(process.env.OTP_MAX_REQUESTS_PER_HOUR) || 3;
const OTP_EXPIRATION_SECONDS = Number(process.env.OTP_EXPIRATION_SECONDS) || 30;
const RESEND_WINDOW_MINUTES = Number(process.env.OTP_RESEND_WINDOW_MINUTES) || 5;
const MAX_RESENDS = Number(process.env.OTP_MAX_RESENDS) || 3;
const ONE_HOUR_MS = 60 * 60 * 1000;
const TWENTY_FOUR_HOURS_MS = 24 * 60 * 60 * 1000;

// Helper function to normalize all email addresses to lowercases and trim whitespace
function normalizeEmail(email) {
  return email.trim().toLowerCase();
}

// Helper function to generate a 6-digit OTP
function generateOTP() {
  const otp = crypto.randomInt(0, 1000000); // generates a random integer between 0 and 999999
  return String(otp).padStart(6, '0'); // ensures the OTP is 6 digits by padding with leading zeros 

}

// Helper function to clean up old OTP requests after one hour
function cleanOldRequests(user, now) {
    user.requests = user.requests.filter(
        (timestamp) => now - timestamp < ONE_HOUR_MS
    )
}

// Helper function to clean up old OTP history entries after 24 hours
function cleanOldOtpHistory(user, now) {
  user.previousOtps = user.previousOtps.filter(
        (entry) => now - entry.timestamp < TWENTY_FOUR_HOURS_MS
    )
}

// Helper function to generate a unique OTP for a user
function generateUniqueOtp(user, now) {
    cleanOldOtpHistory(user, now);
    let otp;
    do {
        otp = generateOTP();
    } while (user.previousOtps.some(entry => entry.otp === otp));

    return otp;
}

// Helper function to create a new user state
function createUserState() {
    return {
        otp: null,
        createdAt: null,
        expiresAt: null,
        resendCount: 0,
        requests: [],
        previousOtps: [],
        used: []
    };
}

// Helper function to check if an OTP is valid for a user
function requestOtp(email) {
  const normalizedEmail = normalizeEmail(email);
  const now = Date.now();

  let user = users.get(normalizedEmail);

  if (!user) {
    user = createUserState();
    users.set(normalizedEmail, user);
  }

  cleanOldRequests(user, now);
  cleanOldOtpHistory(user, now);

  if (user.requests.length >= MAX_REQUESTS_PER_HOUR) {
    return {
      success: false,
      reason: "RATE_LIMIT"
    };
  }

  user.requests.push(now);

  const resendWindow =
    RESEND_WINDOW_MINUTES * 60 * 1000;

  const hasCurrentOtp =
    user.otp !== null &&
    user.createdAt !== null &&
    now - user.createdAt < resendWindow;

  if (hasCurrentOtp) {
    if (user.resendCount >= MAX_RESENDS) {
      return {
        success: false,
        reason: "MAX_RESENDS"
      };
    }

    user.resendCount += 1;
    user.expiresAt =
      now + OTP_EXPIRATION_SECONDS * 1000;

    user.used = false;

    return {
      success: true,
      otp: user.otp,
      type: "resend"
    };
  }

  const otp = generateUniqueOtp(user, now);

  user.otp = otp;
  user.createdAt = now;
  user.expiresAt =
    now + OTP_EXPIRATION_SECONDS * 1000;

  user.resendCount = 0;
  user.used = false;

  user.previousOtps.push({
    otp,
    createdAt: now
  });

  return {
    success: true,
    otp,
    type: "new"
  };
}

// Helper function to verify an OTP for a user
function verifyOtp(email, otp) {
  const normalizedEmail = normalizeEmail(email);
  const now = Date.now();

  const user = users.get(normalizedEmail);

  if (!user) {
    return {
      success: false,
      valid: false,
      reason: "INVALID_OTP"
    };
  }

  if (user.otp === null) {
    return {
      success: false,
      valid: false,
      reason: "INVALID_OTP"
    };
  }

  if (user.used) {
    return {
      success: false,
      valid: false,
      reason: "OTP_ALREADY_USED"
    };
  }

  if (now >= user.expiresAt) {
    return {
      success: false,
      valid: false,
      reason: "OTP_EXPIRED"
    };
  }

  if (otp !== user.otp) {
    return {
      success: false,
      valid: false,
      reason: "INVALID_OTP"
    };
  }

  user.used = true;

  return {
    success: true,
    valid: true
  };
}

module.exports = {
  requestOtp,
  verifyOtp
};