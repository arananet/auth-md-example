// Stub email sender — replace with real provider in production
export async function sendOtp(email: string, otp: string): Promise<void> {
  // Never log the otp value in production
  console.log(`[email stub] Sending OTP to ${email} (otp omitted from log)`);
}
