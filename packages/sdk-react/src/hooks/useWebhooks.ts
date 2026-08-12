/**
 * @authn/react — useWebhooks Hook
 */

import { useState, useCallback, useEffect, useRef } from "react";
import type { AuthnAdminClient } from "@authn/js/admin";
import type {
  WebhookEndpointDTO,
  WebhookDeliveryDTO,
  CreateWebhookEndpointParams,
  UpdateWebhookEndpointParams,
} from "@authn/js/admin";
import { AuthnError, AuthnErrorCode } from "@authn/js";

export interface UseWebhooksReturn {
  endpoints: WebhookEndpointDTO[];
  deliveries: WebhookDeliveryDTO[];
  isLoading: boolean;
  error: AuthnError | null;
  listEndpoints: () => Promise<void>;
  createEndpoint: (
    params: CreateWebhookEndpointParams
  ) => Promise<WebhookEndpointDTO | null>;
  updateEndpoint: (
    params: UpdateWebhookEndpointParams
  ) => Promise<WebhookEndpointDTO | null>;
  deleteEndpoint: (endpointId: string) => Promise<boolean>;
  pingEndpoint: (endpointId: string) => Promise<boolean>;
  rotateSecret: (endpointId: string) => Promise<string | null>;
  listDeliveries: () => Promise<void>;
  redeliver: (deliveryId: string) => Promise<boolean>;
  reset: () => void;
}

export function useWebhooks(adminClient?: AuthnAdminClient): UseWebhooksReturn {
  const [endpoints, setEndpoints] = useState<WebhookEndpointDTO[]>([]);
  const [deliveries, setDeliveries] = useState<WebhookDeliveryDTO[]>([]);
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [error, setError] = useState<AuthnError | null>(null);

  const isMounted = useRef(true);
  useEffect(() => {
    isMounted.current = true;
    return () => {
      isMounted.current = false;
    };
  }, []);

  const reset = useCallback(() => {
    setEndpoints([]);
    setDeliveries([]);
    setIsLoading(false);
    setError(null);
  }, []);

  const listEndpoints = useCallback(async () => {
    if (!adminClient) return;
    setIsLoading(true);
    setError(null);
    try {
      const res = await adminClient.listWebhookEndpoints();
      if (!isMounted.current) return;
      if (res.ok) {
        setEndpoints(res.endpoints);
      } else {
        setError(res.error);
      }
    } catch (err) {
      if (isMounted.current) {
        setError(
          new AuthnError({
            code: AuthnErrorCode.UNKNOWN,
            message:
              err instanceof Error ? err.message : "Failed to list webhook endpoints",
          })
        );
      }
    } finally {
      if (isMounted.current) setIsLoading(false);
    }
  }, [adminClient]);

  const createEndpoint = useCallback(
    async (
      params: CreateWebhookEndpointParams
    ): Promise<WebhookEndpointDTO | null> => {
      if (!adminClient) return null;
      setIsLoading(true);
      setError(null);
      try {
        const res = await adminClient.createWebhookEndpoint(params);
        if (!isMounted.current) return null;
        if (res.ok) {
          setEndpoints((prev) => [...prev, res.endpoint]);
          return res.endpoint;
        } else {
          setError(res.error);
          return null;
        }
      } catch (err) {
        if (isMounted.current) {
          setError(
            new AuthnError({
              code: AuthnErrorCode.UNKNOWN,
              message:
                err instanceof Error
                  ? err.message
                  : "Failed to create webhook endpoint",
            })
          );
        }
        return null;
      } finally {
        if (isMounted.current) setIsLoading(false);
      }
    },
    [adminClient]
  );

  const updateEndpoint = useCallback(
    async (
      params: UpdateWebhookEndpointParams
    ): Promise<WebhookEndpointDTO | null> => {
      if (!adminClient) return null;
      setIsLoading(true);
      setError(null);
      try {
        const res = await adminClient.updateWebhookEndpoint(params);
        if (!isMounted.current) return null;
        if (res.ok) {
          setEndpoints((prev) =>
            prev.map((ep) => (ep.id === res.endpoint.id ? res.endpoint : ep))
          );
          return res.endpoint;
        } else {
          setError(res.error);
          return null;
        }
      } catch (err) {
        if (isMounted.current) {
          setError(
            new AuthnError({
              code: AuthnErrorCode.UNKNOWN,
              message:
                err instanceof Error
                  ? err.message
                  : "Failed to update webhook endpoint",
            })
          );
        }
        return null;
      } finally {
        if (isMounted.current) setIsLoading(false);
      }
    },
    [adminClient]
  );

  const deleteEndpoint = useCallback(
    async (endpointId: string): Promise<boolean> => {
      if (!adminClient) return false;
      setIsLoading(true);
      setError(null);
      try {
        const res = await adminClient.deleteWebhookEndpoint(endpointId);
        if (!isMounted.current) return false;
        if (res.ok) {
          setEndpoints((prev) => prev.filter((ep) => ep.id !== endpointId));
          return true;
        } else {
          setError(res.error);
          return false;
        }
      } catch (err) {
        if (isMounted.current) {
          setError(
            new AuthnError({
              code: AuthnErrorCode.UNKNOWN,
              message:
                err instanceof Error
                  ? err.message
                  : "Failed to delete webhook endpoint",
            })
          );
        }
        return false;
      } finally {
        if (isMounted.current) setIsLoading(false);
      }
    },
    [adminClient]
  );

  const pingEndpoint = useCallback(
    async (endpointId: string): Promise<boolean> => {
      if (!adminClient) return false;
      setIsLoading(true);
      setError(null);
      try {
        const res = await adminClient.pingWebhookEndpoint(endpointId);
        if (!isMounted.current) return false;
        if (res.ok) {
          return true;
        } else {
          setError(res.error);
          return false;
        }
      } catch (err) {
        if (isMounted.current) {
          setError(
            new AuthnError({
              code: AuthnErrorCode.UNKNOWN,
              message:
                err instanceof Error ? err.message : "Failed to ping webhook endpoint",
            })
          );
        }
        return false;
      } finally {
        if (isMounted.current) setIsLoading(false);
      }
    },
    [adminClient]
  );

  const rotateSecret = useCallback(
    async (endpointId: string): Promise<string | null> => {
      if (!adminClient) return null;
      setIsLoading(true);
      setError(null);
      try {
        const res = await adminClient.rotateWebhookSecret(endpointId);
        if (!isMounted.current) return null;
        if (res.ok) {
          return res.secret;
        } else {
          setError(res.error);
          return null;
        }
      } catch (err) {
        if (isMounted.current) {
          setError(
            new AuthnError({
              code: AuthnErrorCode.UNKNOWN,
              message:
                err instanceof Error
                  ? err.message
                  : "Failed to rotate webhook secret",
            })
          );
        }
        return null;
      } finally {
        if (isMounted.current) setIsLoading(false);
      }
    },
    [adminClient]
  );

  const listDeliveries = useCallback(async () => {
    if (!adminClient) return;
    setIsLoading(true);
    setError(null);
    try {
      const res = await adminClient.listWebhookDeliveries();
      if (!isMounted.current) return;
      if (res.ok) {
        setDeliveries(res.deliveries);
      } else {
        setError(res.error);
      }
    } catch (err) {
      if (isMounted.current) {
        setError(
          new AuthnError({
            code: AuthnErrorCode.UNKNOWN,
            message:
              err instanceof Error ? err.message : "Failed to list webhook deliveries",
          })
        );
      }
    } finally {
      if (isMounted.current) setIsLoading(false);
    }
  }, [adminClient]);

  const redeliver = useCallback(
    async (deliveryId: string): Promise<boolean> => {
      if (!adminClient) return false;
      setIsLoading(true);
      setError(null);
      try {
        const res = await adminClient.redeliverWebhook(deliveryId);
        if (!isMounted.current) return false;
        if (res.ok) {
          return true;
        } else {
          setError(res.error);
          return false;
        }
      } catch (err) {
        if (isMounted.current) {
          setError(
            new AuthnError({
              code: AuthnErrorCode.UNKNOWN,
              message:
                err instanceof Error ? err.message : "Failed to redeliver webhook",
            })
          );
        }
        return false;
      } finally {
        if (isMounted.current) setIsLoading(false);
      }
    },
    [adminClient]
  );

  return {
    endpoints,
    deliveries,
    isLoading,
    error,
    listEndpoints,
    createEndpoint,
    updateEndpoint,
    deleteEndpoint,
    pingEndpoint,
    rotateSecret,
    listDeliveries,
    redeliver,
    reset,
  };
}
