import { useQuery } from "@tanstack/react-query";
import { api } from "./types";
export interface Identity {
  id: string;
  role: string;
  scopes: string[];
  admin: boolean;
  audit: boolean;
}
export function useIdentity() {
  return useQuery({
    queryKey: ["identity"],
    queryFn: () => api<Identity>("/api/auth/me"),
    refetchInterval: 30000,
    staleTime: 10000,
  });
}
export function permits(identity: Identity | undefined, scope: string) {
  return !!identity && (identity.admin || identity.scopes.includes(scope));
}
