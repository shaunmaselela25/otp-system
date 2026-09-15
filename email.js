function sendOtpEmail(email, otp) {
  console.log("");
  console.log("===== OTP EMAIL =====");
  console.log(`To: ${email}`);
  console.log(`OTP: ${otp}`);
  console.log("=====================");
  console.log("");
}

module.exports = {
  sendOtpEmail
};