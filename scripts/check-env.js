/* eslint-disable no-console */
import 'dotenv/config';

function checkMissing(vars) {
  const missing = vars.reduce((arr, key) => {
    if (!process.env[key]) {
      arr.push(key);
    }
    return arr;
  }, []);

  if (missing.length) {
    console.log(`The following environment variables are not defined:`);
    for (const item of missing) {
      console.log(' - ', item);
    }
    process.exit(1);
  }
}

function checkAppSecret() {
  const appSecret = process.env.APP_SECRET;
  
  if (!appSecret) {
    console.log('SECURITY ERROR: APP_SECRET environment variable is required but not set.');
    console.log('This is a critical security configuration.');
    console.log('Generate a secure secret using: openssl rand -base64 32');
    process.exit(1);
  }
  
  if (appSecret === process.env.DATABASE_URL) {
    console.log('SECURITY ERROR: APP_SECRET must not be the same as DATABASE_URL.');
    console.log('This is a security vulnerability. Please generate a unique secret.');
    process.exit(1);
  }
  
  if (appSecret.length < 32) {
    console.log('SECURITY ERROR: APP_SECRET must be at least 32 characters long for security.');
    console.log('Generate a secure secret using: openssl rand -base64 32');
    process.exit(1);
  }
  
  // Check for common weak patterns
  if (/^(secret|password|123|test|demo|development|dev|prod|production)/i.test(appSecret)) {
    console.log('SECURITY WARNING: APP_SECRET appears to use a weak pattern.');
    console.log('Consider generating a stronger secret using: openssl rand -base64 32');
    process.exit(1);
  }
}

// Always check APP_SECRET for security
checkAppSecret();

if (!process.env.SKIP_DB_CHECK && !process.env.DATABASE_TYPE) {
  checkMissing(['DATABASE_URL']);
}

if (process.env.CLOUD_URL) {
  checkMissing(['CLOUD_URL', 'CLICKHOUSE_URL', 'REDIS_URL']);
}
