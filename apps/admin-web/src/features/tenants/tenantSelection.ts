type ResolveAutoSelectedTenantIdInput = {
  isAuthenticated: boolean;
  tenantIds: string[];
  selectedTenantId?: string;
};

export const resolveAutoSelectedTenantId = ({
  isAuthenticated,
  tenantIds,
  selectedTenantId
}: ResolveAutoSelectedTenantIdInput): string | undefined => {
  if (!isAuthenticated || tenantIds.length !== 1) {
    return undefined;
  }

  const singleTenantId = tenantIds[0];
  if (!selectedTenantId) {
    return singleTenantId;
  }

  return selectedTenantId === singleTenantId ? undefined : singleTenantId;
};
