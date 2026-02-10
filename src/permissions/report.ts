import type { Report } from '@/generated/prisma/client';
import type { Auth } from '@/lib/types';
import { canViewWebsite } from './website';

export async function canViewReport(auth: Auth, report: Report) {
  // Admin users can view all reports (user auth only)
  if (auth.authMethod === 'user' && auth.user?.isAdmin) {
    return true;
  }

  // Report owner can view their own reports (user auth only)
  if (auth.authMethod === 'user' && auth.user?.id === report.userId) {
    return true;
  }

  // Check if user/share token can view the associated website
  return !!(await canViewWebsite(auth, report.websiteId));
}

export async function canUpdateReport({ user, authMethod }: Auth, report: Report) {
  // Only user authentication allowed for update operations
  if (authMethod !== 'user' || !user) {
    return false;
  }

  if (user.isAdmin) {
    return true;
  }

  return user.id === report.userId;
}

export async function canDeleteReport(auth: Auth, report: Report) {
  return canUpdateReport(auth, report);
}
