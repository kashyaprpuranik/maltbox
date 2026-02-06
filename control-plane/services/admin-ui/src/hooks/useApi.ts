import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { api } from '../api/client';
import type {
  AuditLogFilters,
  CreateSecretRequest,
  CreateAllowlistEntryRequest,
  CreateRateLimitRequest,
  UpdateRateLimitRequest,
  CreateApiTokenRequest,
  CreateTenantRequest,
  CreateTenantIpAclRequest,
  UpdateTenantIpAclRequest,
} from '../types/api';

// Health
export function useHealth() {
  return useQuery({
    queryKey: ['health'],
    queryFn: api.getHealth,
    refetchInterval: 30000,
  });
}

// Data Planes / Agents
export function useDataPlanes() {
  return useQuery({
    queryKey: ['dataPlanes'],
    queryFn: api.getDataPlanes,
    refetchInterval: 10000,
  });
}

// Alias for useDataPlanes - for use in forms/dropdowns
export const useAgents = useDataPlanes;

// Secrets
export function useSecrets() {
  return useQuery({
    queryKey: ['secrets'],
    queryFn: api.getSecrets,
  });
}

export function useCreateSecret() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (data: CreateSecretRequest) => api.createSecret(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['secrets'] });
    },
  });
}

export function useRotateSecret() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ name, newValue }: { name: string; newValue: string }) =>
      api.rotateSecret(name, newValue),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['secrets'] });
    },
  });
}

export function useDeleteSecret() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (name: string) => api.deleteSecret(name),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['secrets'] });
    },
  });
}

// Allowlist
export function useAllowlist(type?: string) {
  return useQuery({
    queryKey: ['allowlist', type],
    queryFn: () => api.getAllowlist(type),
  });
}

export function useAddAllowlistEntry() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (data: CreateAllowlistEntryRequest) =>
      api.addAllowlistEntry(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['allowlist'] });
    },
  });
}

export function useUpdateAllowlistEntry() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({
      id,
      data,
    }: {
      id: number;
      data: Partial<CreateAllowlistEntryRequest>;
    }) => api.updateAllowlistEntry(id, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['allowlist'] });
    },
  });
}

export function useDeleteAllowlistEntry() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (id: number) => api.deleteAllowlistEntry(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['allowlist'] });
    },
  });
}

// Audit Logs
export function useAuditLogs(filters: AuditLogFilters = {}) {
  return useQuery({
    queryKey: ['auditLogs', filters],
    queryFn: () => api.getAuditLogs(filters),
  });
}

// Agent Management (per data plane)
export function useAgentStatus(agentId: string | null) {
  return useQuery({
    queryKey: ['agentStatus', agentId],
    queryFn: () => api.getAgentStatus(agentId!),
    enabled: !!agentId,
    refetchInterval: 10000,
  });
}

export function useWipeAgent() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ agentId, wipeWorkspace }: { agentId: string; wipeWorkspace: boolean }) =>
      api.wipeAgent(agentId, wipeWorkspace),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['agentStatus'] });
      queryClient.invalidateQueries({ queryKey: ['dataPlanes'] });
    },
  });
}

export function useRestartAgent() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (agentId: string) => api.restartAgent(agentId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['agentStatus'] });
      queryClient.invalidateQueries({ queryKey: ['dataPlanes'] });
    },
  });
}

export function useStopAgent() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (agentId: string) => api.stopAgent(agentId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['agentStatus'] });
      queryClient.invalidateQueries({ queryKey: ['dataPlanes'] });
    },
  });
}

export function useStartAgent() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (agentId: string) => api.startAgent(agentId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['agentStatus'] });
      queryClient.invalidateQueries({ queryKey: ['dataPlanes'] });
    },
  });
}

// Rate Limits
export function useRateLimits() {
  return useQuery({
    queryKey: ['rateLimits'],
    queryFn: api.getRateLimits,
  });
}

export function useCreateRateLimit() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (data: CreateRateLimitRequest) => api.createRateLimit(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['rateLimits'] });
    },
  });
}

export function useUpdateRateLimit() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ id, data }: { id: number; data: UpdateRateLimitRequest }) =>
      api.updateRateLimit(id, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['rateLimits'] });
    },
  });
}

export function useDeleteRateLimit() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (id: number) => api.deleteRateLimit(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['rateLimits'] });
    },
  });
}

// API Tokens
export function useTokens() {
  return useQuery({
    queryKey: ['tokens'],
    queryFn: api.getTokens,
  });
}

export function useCreateToken() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (data: CreateApiTokenRequest) => api.createToken(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['tokens'] });
    },
  });
}

export function useDeleteToken() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (id: number) => api.deleteToken(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['tokens'] });
    },
  });
}

export function useUpdateToken() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ id, enabled }: { id: number; enabled: boolean }) =>
      api.updateToken(id, enabled),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['tokens'] });
    },
  });
}

// Agent Approval
export function useApproveAgent() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (agentId: string) => api.approveAgent(agentId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['dataPlanes'] });
      queryClient.invalidateQueries({ queryKey: ['agentStatus'] });
    },
  });
}

export function useRejectAgent() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (agentId: string) => api.rejectAgent(agentId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['dataPlanes'] });
      queryClient.invalidateQueries({ queryKey: ['agentStatus'] });
    },
  });
}

export function useRevokeAgent() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (agentId: string) => api.revokeAgent(agentId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['dataPlanes'] });
      queryClient.invalidateQueries({ queryKey: ['agentStatus'] });
    },
  });
}

// Tenants
export function useTenants(enabled: boolean = true) {
  return useQuery({
    queryKey: ['tenants'],
    queryFn: api.getTenants,
    enabled,
  });
}

export function useCreateTenant() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (data: CreateTenantRequest) => api.createTenant(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['tenants'] });
    },
  });
}

export function useDeleteTenant() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (id: number) => api.deleteTenant(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['tenants'] });
    },
  });
}

// IP ACLs
export function useTenantIpAcls(tenantId: number | null) {
  return useQuery({
    queryKey: ['tenantIpAcls', tenantId],
    queryFn: () => api.getTenantIpAcls(tenantId!),
    enabled: !!tenantId,
  });
}

export function useCreateTenantIpAcl() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({
      tenantId,
      data,
    }: {
      tenantId: number;
      data: CreateTenantIpAclRequest;
    }) => api.createTenantIpAcl(tenantId, data),
    onSuccess: (_, { tenantId }) => {
      queryClient.invalidateQueries({ queryKey: ['tenantIpAcls', tenantId] });
    },
  });
}

export function useUpdateTenantIpAcl() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({
      tenantId,
      aclId,
      data,
    }: {
      tenantId: number;
      aclId: number;
      data: UpdateTenantIpAclRequest;
    }) => api.updateTenantIpAcl(tenantId, aclId, data),
    onSuccess: (_, { tenantId }) => {
      queryClient.invalidateQueries({ queryKey: ['tenantIpAcls', tenantId] });
    },
  });
}

export function useDeleteTenantIpAcl() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ tenantId, aclId }: { tenantId: number; aclId: number }) =>
      api.deleteTenantIpAcl(tenantId, aclId),
    onSuccess: (_, { tenantId }) => {
      queryClient.invalidateQueries({ queryKey: ['tenantIpAcls', tenantId] });
    },
  });
}
