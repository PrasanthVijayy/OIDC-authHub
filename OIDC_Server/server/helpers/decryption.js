import crypto from "node:crypto";
import dotenv from "dotenv";
dotenv.config();

async function decryptData(encryptedData) {
  try {
    const SYMMETRIC_KEY = Buffer.from(process.env.SYMMETRIC_KEY);
    
    const parts = encryptedData.split(":");
    if (parts.length !== 3) throw new Error("Invalid encrypted format!");

    const iv = Buffer.from(parts[0], "base64");
    const ciphertext = Buffer.from(parts[1], "base64");
    const authTag = Buffer.from(parts[2], "base64");

    const decipher = crypto.createDecipheriv("aes-256-gcm", SYMMETRIC_KEY, iv);
    decipher.setAuthTag(authTag); // ✅ Set authentication tag for verification

    let decrypted = decipher.update(ciphertext);
    decrypted = Buffer.concat([decrypted, decipher.final()]);

    return decrypted.toString("utf-8");
  } catch (error) {
    console.error("❌ Decryption failed:", error.message);
    return null;
  }
}

export { decryptData };
