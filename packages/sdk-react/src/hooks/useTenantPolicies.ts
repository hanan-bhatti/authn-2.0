import { useState, useCallback, useRef, useEffect } from "react";
import type {
  AuthnAdminClient,
  PasswordPolicyDTO,
  SecurityPolicyDTO,
  RecoveryPolicyDTO,
  UpdatePasswordPolicyParams,
  UpdateSecurityPolicyParams,
  UpdateRecoveryPolicyParams,
} from "@authn/js/admin";

export function useTenantPolicies(adminClient?: AuthnAdminClient | null) {
  const [passwordPolicy, setPasswordPolicy] = useState<PasswordPolicyDTO | null>(null);
  const [securityPolicy, setSecurityPolicy] = useState<SecurityPolicyDTO | null>(null);
  const [recoveryPolicy, setRecoveryPolicy] = useState<RecoveryPolicyDTO | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const isMounted = useRef(true);

  useEffect(() => {
    isMounted.current = true;
    return () => {
      isMounted.current = false;
    };
  }, []);

  const loadPolicies = useCallback(async () => {
    if (!adminClient) return;
    setIsLoading(true);
    setError(null);

    try {
      const [pwdRes, secRes, recRes] = await Promise.all([
        adminClient.getPasswordPolicy(),
        adminClient.getSecurityPolicy(),
        adminClient.getRecoveryPolicy(),
      ]);

      if (!isMounted.current) return;

      if (pwdRes.ok) setPasswordPolicy(pwdRes.policy);
      if (secRes.ok) setSecurityPolicy(secRes.policy);
      if (recRes.ok) setRecoveryPolicy(recRes.policy);

      if (!pwdRes.ok) setError(pwdRes.error.message);
      else if (!secRes.ok) setError(secRes.error.message);
      else if (!recRes.ok) setError(recRes.error.message);
    } catch (err: any) {
      if (isMounted.current) {
        setError(err.message || "Failed to load tenant policies");
      }
    } finally {
      if (isMounted.current) {
        setIsLoading(false);
      }
    }
  }, [adminClient]);

  const updatePasswordPolicy = async (params: UpdatePasswordPolicyParams) => {
    if (!adminClient) return { ok: false, error: new Error("Admin client required") };
    setIsLoading(true);
    const res = await adminClient.updatePasswordPolicy(params);
    if (isMounted.current) {
      setIsLoading(false);
      if (res.ok) setPasswordPolicy(res.policy);
      else setError(res.error.message);
    }
    return res;
  };

  const updateSecurityPolicy = async (params: UpdateSecurityPolicyParams) => {
    if (!adminClient) return { ok: false, error: new Error("Admin client required") };
    setIsLoading(true);
    const res = await adminClient.updateSecurityPolicy(params);
    if (isMounted.current) {
      setIsLoading(false);
      if (res.ok) setSecurityPolicy(res.policy);
      else setError(res.error.message);
    }
    return res;
  };

  const updateRecoveryPolicy = async (params: UpdateRecoveryPolicyParams) => {
    if (!adminClient) return { ok: false, error: new Error("Admin client required") };
    setIsLoading(true);
    const res = await adminClient.updateRecoveryPolicy(params);
    if (isMounted.current) {
      setIsLoading(false);
      if (res.ok) setRecoveryPolicy(res.policy);
      else setError(res.error.message);
    }
    return res;
  };

  const rotateJWKS = async () => {
    if (!adminClient) return { ok: false, error: new Error("Admin client required") };
    setIsLoading(true);
    const res = await adminClient.rotateJWKS();
    if (isMounted.current) {
      setIsLoading(false);
      if (!res.ok) setError(res.error.message);
    }
    return res;
  };

  return {
    passwordPolicy,
    securityPolicy,
    recoveryPolicy,
    isLoading,
    error,
    loadPolicies,
    updatePasswordPolicy,
    updateSecurityPolicy,
    updateRecoveryPolicy,
    rotateJWKS,
  };
}
