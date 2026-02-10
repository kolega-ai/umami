import crypto from 'node:crypto';
import { v4, v5, v7 } from 'uuid';

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 16;
const SALT_LENGTH = 64;
const TAG_LENGTH = 16;
const TAG_POSITION = SALT_LENGTH + IV_LENGTH;
const ENC_POSITION = TAG_POSITION + TAG_LENGTH;

const HASH_ALGO = 'sha512';
const HASH_ENCODING = 'hex';

const getKey = (password: string, salt: Buffer) =>
  crypto.pbkdf2Sync(password, salt, 10000, 32, 'sha512');

export function encrypt(value: any, secret: any) {
  const iv = crypto.randomBytes(IV_LENGTH);
  const salt = crypto.randomBytes(SALT_LENGTH);
  const key = getKey(secret, salt);

  const cipher = crypto.createCipheriv(ALGORITHM, key, iv);

  const encrypted = Buffer.concat([cipher.update(String(value), 'utf8'), cipher.final()]);

  const tag = cipher.getAuthTag();

  return Buffer.concat([salt, iv, tag, encrypted]).toString('base64');
}

export function decrypt(value: any, secret: any) {
  const str = Buffer.from(String(value), 'base64');
  const salt = str.subarray(0, SALT_LENGTH);
  const iv = str.subarray(SALT_LENGTH, TAG_POSITION);
  const tag = str.subarray(TAG_POSITION, ENC_POSITION);
  const encrypted = str.subarray(ENC_POSITION);

  const key = getKey(secret, salt);

  const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);

  decipher.setAuthTag(tag);

  return decipher.update(encrypted) + decipher.final('utf8');
}

export function hash(...args: string[]) {
  return crypto.createHash(HASH_ALGO).update(args.join('')).digest(HASH_ENCODING);
}

export function md5(...args: string[]) {
  return crypto.createHash('md5').update(args.join('')).digest('hex');
}

export function secret() {
  const appSecret = process.env.APP_SECRET;
  
  if (!appSecret) {
    throw new Error(
      'SECURITY ERROR: APP_SECRET environment variable is required but not set. ' +
      'This is a critical security configuration. ' +
      'Generate a secure secret using: openssl rand -base64 32'
    );
  }
  
  // Additional validation to ensure it's not accidentally set to DATABASE_URL
  if (appSecret === process.env.DATABASE_URL) {
    throw new Error(
      'SECURITY ERROR: APP_SECRET must not be the same as DATABASE_URL. ' +
      'This is a security vulnerability. Please generate a unique secret.'
    );
  }
  
  // Ensure minimum entropy
  if (appSecret.length < 32) {
    throw new Error(
      'SECURITY ERROR: APP_SECRET must be at least 32 characters long for security. ' +
      'Generate a secure secret using: openssl rand -base64 32'
    );
  }
  
  return hash(appSecret);
}

export function uuid(...args: any) {
  if (args.length) {
    return v5(hash(...args, secret()), v5.DNS);
  }

  return process.env.USE_UUIDV7 ? v7() : v4();
}
