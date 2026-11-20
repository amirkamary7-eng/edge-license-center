import type { AdminRole } from '../../shared/types';

export type AdminPermission =
  | 'dashboard:read'
  | 'users:read'
  | 'users:write'
  | 'orders:read'
  | 'orders:write'
  | 'payments:read'
  | 'payments:verify'
  | 'subscriptions:read'
  | 'subscriptions:write'
  | 'licenses:read'
  | 'licenses:write'
  | 'plans:read'
  | 'plans:write'
  | 'reports:finance'
  | 'reports:security'
  | 'admins:read'
  | 'admins:write'
  | 'settings:read'
  | 'settings:write';

export const ROLE_PERMISSIONS: Record<AdminRole, readonly AdminPermission[]> = {
  super_admin: [
    'dashboard:read',
    'users:read',
    'users:write',
    'orders:read',
    'orders:write',
    'payments:read',
    'payments:verify',
    'subscriptions:read',
    'subscriptions:write',
    'licenses:read',
    'licenses:write',
    'plans:read',
    'plans:write',
    'reports:finance',
    'reports:security',
    'admins:read',
    'admins:write',
    'settings:read',
    'settings:write',
  ],
  admin: [
    'dashboard:read',
    'users:read',
    'users:write',
    'orders:read',
    'orders:write',
    'payments:read',
    'subscriptions:read',
    'subscriptions:write',
    'licenses:read',
    'licenses:write',
    'plans:read',
    'reports:finance',
    'reports:security',
    'admins:read',
    'settings:read',
  ],
  finance: [
    'dashboard:read',
    'orders:read',
    'payments:read',
    'payments:verify',
    'subscriptions:read',
    'plans:read',
    'reports:finance',
  ],
  support: [
    'dashboard:read',
    'users:read',
    'orders:read',
    'payments:read',
    'subscriptions:read',
    'licenses:read',
    'plans:read',
  ],
  auditor: [
    'dashboard:read',
    'users:read',
    'orders:read',
    'payments:read',
    'subscriptions:read',
    'licenses:read',
    'plans:read',
    'reports:finance',
    'reports:security',
    'admins:read',
    'settings:read',
  ],
};

export function hasAdminPermission(
  role: AdminRole | null | undefined,
  permission: AdminPermission,
  extraPermissions: string[] = []
): boolean {
  if (!role) return false;
  if (ROLE_PERMISSIONS[role]?.includes(permission)) return true;
  return extraPermissions.includes(permission);
}

export function getEffectivePermissions(
  role: AdminRole | null | undefined,
  extraPermissions: string[] = []
): string[] {
  if (!role) return [];
  return Array.from(new Set([...ROLE_PERMISSIONS[role], ...extraPermissions]));
}
