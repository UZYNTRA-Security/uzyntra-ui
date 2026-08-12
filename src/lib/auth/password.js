import "server-only";

import crypto from "node:crypto";
import argon2 from "argon2";

export const PASSWORD_POLICY = {
  minLength: 12,
  maxLength: 1024,
};

export const ARGON2ID_OPTIONS = {
  type: argon2.argon2id,
  memoryCost: 19_456,
  timeCost: 2,
  parallelism: 1,
};

export function validatePasswordPolicy(password) {
  if (typeof password !== "string") {
    return { valid: false, reason: "password must be a string" };
  }

  if (password.length < PASSWORD_POLICY.minLength) {
    return { valid: false, reason: "password is too short" };
  }

  if (password.length > PASSWORD_POLICY.maxLength) {
    return { valid: false, reason: "password is too long" };
  }

  return { valid: true };
}

export async function hashPassword(password) {
  const policy = validatePasswordPolicy(password);
  if (!policy.valid) {
    throw new Error(policy.reason);
  }

  return argon2.hash(pepperedPassword(password), ARGON2ID_OPTIONS);
}

export async function verifyPassword(password, passwordHash) {
  if (typeof password !== "string" || typeof passwordHash !== "string" || !passwordHash) {
    return false;
  }

  try {
    return await argon2.verify(passwordHash, pepperedPassword(password));
  } catch (error) {
    if (error?.message?.startsWith("AUTH_PASSWORD_PEPPER")) {
      throw error;
    }

    return false;
  }
}

function pepperedPassword(password) {
  const pepper = passwordPepper();
  return crypto.createHmac("sha256", pepper).update(password, "utf8").digest("base64");
}

function passwordPepper() {
  const pepper = process.env.AUTH_PASSWORD_PEPPER;
  if (!pepper || pepper.length < 32) {
    throw new Error("AUTH_PASSWORD_PEPPER must be at least 32 characters");
  }

  return pepper;
}
