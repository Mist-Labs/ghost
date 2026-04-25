import crypto from "crypto";

const SPECIAL_CHAR_PATTERN = /[^A-Za-z0-9]/;

export function validatePassword(password: string) {
  if (password.length < 7) {
    return "Password must be at least 7 characters long.";
  }

  if (!SPECIAL_CHAR_PATTERN.test(password)) {
    return "Password must include at least one special character.";
  }

  return null;
}

export async function hashPassword(password: string) {
  const salt = crypto.randomBytes(16).toString("hex");
  const derivedKey = await scrypt(password, salt);
  return `scrypt:${salt}:${derivedKey.toString("hex")}`;
}

export async function verifyPassword(password: string, storedHash: string) {
  const [algorithm, salt, expectedHex] = storedHash.split(":");
  if (algorithm !== "scrypt" || !salt || !expectedHex) {
    return false;
  }

  const actual = await scrypt(password, salt);
  const expected = Buffer.from(expectedHex, "hex");

  if (expected.length !== actual.length) {
    return false;
  }

  return crypto.timingSafeEqual(expected, actual);
}

function scrypt(password: string, salt: string) {
  return new Promise<Buffer>((resolve, reject) => {
    crypto.scrypt(password, salt, 64, (error, derivedKey) => {
      if (error) {
        reject(error);
        return;
      }

      resolve(derivedKey as Buffer);
    });
  });
}
