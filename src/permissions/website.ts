import { hasPermission } from '@/lib/auth';
import { PERMISSIONS } from '@/lib/constants';
import type { Auth } from '@/lib/types';
import { getLink, getPixel, getTeamUser, getWebsite } from '@/queries/prisma';

export async function canViewWebsite({ user, shareToken, authMethod }: Auth, websiteId: string) {
  // Admin users always have access
  if (authMethod === 'user' && user?.isAdmin) {
    return true;
  }

  // Share token access - restricted to the specific website
  if (authMethod === 'share' && shareToken?.websiteId === websiteId) {
    return true;
  }

  // User authentication - check ownership and team permissions
  if (authMethod === 'user' && user) {
    const website = await getWebsite(websiteId);
    const link = await getLink(websiteId);
    const pixel = await getPixel(websiteId);

    const entity = website || link || pixel;

    if (!entity) {
      return false;
    }

    if (entity.userId) {
      return user.id === entity.userId;
    }

    if (entity.teamId) {
      const teamUser = await getTeamUser(entity.teamId, user.id);
      return !!teamUser;
    }
  }

  return false;
}

export async function canViewWebsiteUserOnly({ user, authMethod }: Auth, websiteId: string) {
  // Only allow user authentication for this function
  if (authMethod !== 'user' || !user) {
    return false;
  }

  if (user.isAdmin) {
    return true;
  }

  const website = await getWebsite(websiteId);
  const link = await getLink(websiteId);
  const pixel = await getPixel(websiteId);

  const entity = website || link || pixel;

  if (!entity) {
    return false;
  }

  if (entity.userId) {
    return user.id === entity.userId;
  }

  if (entity.teamId) {
    const teamUser = await getTeamUser(entity.teamId, user.id);
    return !!teamUser;
  }

  return false;
}

export async function canViewAllWebsites({ user, authMethod }: Auth) {
  // Only user authentication allowed for admin operations
  if (authMethod !== 'user' || !user) {
    return false;
  }
  
  return user.isAdmin;
}

export async function canCreateWebsite({ user, authMethod }: Auth) {
  // Only user authentication allowed for creation operations
  if (authMethod !== 'user' || !user) {
    return false;
  }

  if (user.isAdmin) {
    return true;
  }

  return hasPermission(user.role, PERMISSIONS.websiteCreate);
}

export async function canUpdateWebsite({ user, authMethod }: Auth, websiteId: string) {
  // Only user authentication allowed for update operations
  if (authMethod !== 'user' || !user) {
    return false;
  }

  if (user.isAdmin) {
    return true;
  }

  const website = await getWebsite(websiteId);

  if (!website) {
    return false;
  }

  if (website.userId) {
    return user.id === website.userId;
  }

  if (website.teamId) {
    const teamUser = await getTeamUser(website.teamId, user.id);

    return teamUser && hasPermission(teamUser.role, PERMISSIONS.websiteUpdate);
  }

  return false;
}

export async function canDeleteWebsite({ user, authMethod }: Auth, websiteId: string) {
  // Only user authentication allowed for delete operations
  if (authMethod !== 'user' || !user) {
    return false;
  }

  if (user.isAdmin) {
    return true;
  }

  const website = await getWebsite(websiteId);

  if (!website) {
    return false;
  }

  if (website.userId) {
    return user.id === website.userId;
  }

  if (website.teamId) {
    const teamUser = await getTeamUser(website.teamId, user.id);

    return teamUser && hasPermission(teamUser.role, PERMISSIONS.websiteDelete);
  }

  return false;
}

export async function canTransferWebsiteToUser({ user, authMethod }: Auth, websiteId: string, userId: string) {
  // Only user authentication allowed for transfer operations
  if (authMethod !== 'user' || !user) {
    return false;
  }

  const website = await getWebsite(websiteId);

  if (!website) {
    return false;
  }

  if (website.teamId && user.id === userId) {
    const teamUser = await getTeamUser(website.teamId, userId);

    return teamUser && hasPermission(teamUser.role, PERMISSIONS.websiteTransferToUser);
  }

  return false;
}

export async function canTransferWebsiteToTeam({ user, authMethod }: Auth, websiteId: string, teamId: string) {
  // Only user authentication allowed for transfer operations
  if (authMethod !== 'user' || !user) {
    return false;
  }

  const website = await getWebsite(websiteId);

  if (!website) {
    return false;
  }

  if (website.userId && website.userId === user.id) {
    const teamUser = await getTeamUser(teamId, user.id);

    return teamUser && hasPermission(teamUser.role, PERMISSIONS.websiteTransferToTeam);
  }

  return false;
}
