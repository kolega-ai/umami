# 🔐 Critical Security Update - Admin User Vulnerability

## Overview

This update fixes a **critical security vulnerability** (CWE-798: Use of Hard-coded Credentials) that affected all Umami installations using the default migration files.

## The Vulnerability

Previous versions of Umami included a hardcoded admin user in the database migration file (`prisma/migrations/01_init/migration.sql`) with predictable credentials. This created a universal backdoor that could allow unauthorized access to any Umami installation.

**Affected versions:** All versions using the original migration files  
**Severity:** Critical (CVSS 9.8)  
**Risk:** Complete compromise of analytics data and system control

## What's Fixed

1. **Removed hardcoded admin user** from migration files
2. **Created secure setup process** for admin user creation
3. **Added migration script** to disable vulnerable existing accounts
4. **Implemented proper credential handling** with environment variable support

## For New Installations

After setting up the database, create your admin user securely:

```bash
# Interactive setup (recommended for development)
npm run setup-admin

# Or using environment variables (recommended for production)
UMAMI_ADMIN_USERNAME=youradmin UMAMI_ADMIN_PASSWORD=your_secure_password npm run setup-admin
```

## For Existing Installations

**IMMEDIATE ACTION REQUIRED:**

1. **Run the security migration** to disable vulnerable accounts:
   ```bash
   npm run migrate-admin-security
   ```

2. **Create a new admin user** with secure credentials:
   ```bash
   npm run setup-admin
   ```

3. **Review your logs** for any suspicious login activity

## Security Best Practices

- Use strong, unique passwords for admin accounts
- Consider implementing multi-factor authentication
- Regularly rotate admin credentials
- Monitor access logs for unauthorized attempts
- Keep Umami updated to the latest version

## Environment Variables

For production deployments, set these environment variables:

```bash
# Optional: Pre-configure admin credentials
UMAMI_ADMIN_USERNAME=your_admin_username
UMAMI_ADMIN_PASSWORD=your_secure_password

# Required: Database connection
DATABASE_URL=your_database_connection_string
```

## Scripts Added

- `npm run setup-admin` - Create initial admin user securely
- `npm run migrate-admin-security` - Check and disable vulnerable admin accounts

## Compliance

This fix addresses:
- **CWE-798**: Use of Hard-coded Credentials
- **OWASP A07:2021**: Identification and Authentication Failures
- **OWASP A07:2025**: Authentication Failures

## Need Help?

If you need assistance with this security update:

1. Check existing admin users: Review your user management interface
2. Run the security migration: `npm run migrate-admin-security`
3. Create new admin user: `npm run setup-admin`
4. Contact support if you encounter issues

---

**This is a critical security update. Please apply it immediately to all Umami installations.**