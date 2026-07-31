import { AuthnConfig, AuthResponse, AuthStateCallback, Session, User } from "./types";

export class AuthnClient {
  private publishableKey: string;
  private baseUrl: string;
  private clientType: "web" | "native";
  private autoRefresh: boolean;
  private currentSession: Session | null = null;
  private refreshTimer: ReturnType<typeof setTimeout> | null = null;
  private stateListeners: Set<AuthStateCallback> = new Set();

  constructor(config: AuthnConfig) {
    this.publishableKey = config.publishableKey;
    this.baseUrl = config.baseUrl || "https://api.authn.com";
    this.clientType = config.clientType || "web";
    this.autoRefresh = config.autoRefresh !== false;
  }

  private getHeaders(): Record<string, string> {
    return {
      "Content-Type": "application/json",
      "X-Authn-Publishable-Key": this.publishableKey,
      "X-Authn-Client-Type": this.clientType,
    };
  }

  async signInWithPassword(email: string, password: string): Promise<AuthResponse> {
    const response = await fetch(`${this.baseUrl}/v1/client/auth/login`, {
      method: "POST",
      headers: this.getHeaders(),
      credentials: "include",
      body: JSON.stringify({ email, password }),
    });

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      return { error: errorData.message || "Failed to sign in" };
    }

    const data: AuthResponse = await response.json();
    if (data.session) {
      this.setSession(data.session);
    }
    return data;
  }

  /**
   * Waits for real-time Push 2FA approval over WebSocket.
   * Automatically rejects with a timeout error if 120s TTL expires or signal is aborted.
   */
  async waitForPushApproval(twoFactorToken: string, options?: { signal?: AbortSignal }): Promise<Session> {
    return new Promise((resolve, reject) => {
      const wsUrl = `${this.baseUrl.replace(/^http/, "ws")}/v1/client/ws/2fa?two_factor_token=${twoFactorToken}`;
      const socket = new WebSocket(wsUrl);

      const timeoutTimer = setTimeout(() => {
        socket.close();
        reject(new Error("Push approval timed out after 120 seconds. Please try again or use another 2FA method."));
      }, 120000);

      if (options?.signal) {
        options.signal.addEventListener("abort", () => {
          clearTimeout(timeoutTimer);
          socket.close();
          reject(new Error("Push approval cancelled by user."));
        });
      }

      socket.onmessage = async (event) => {
        try {
          const payload = JSON.parse(event.data);
          if (payload.event === "2fa_approved" && payload.exchangeToken) {
            clearTimeout(timeoutTimer);
            socket.close();
            const session = await this.exchange2FAToken(payload.exchangeToken);
            resolve(session);
          } else if (payload.event === "2fa_rejected") {
            clearTimeout(timeoutTimer);
            socket.close();
            reject(new Error("Push notification login request was denied by the user."));
          }
        } catch (err) {
          clearTimeout(timeoutTimer);
          reject(err);
        }
      };

      socket.onerror = (err) => {
        clearTimeout(timeoutTimer);
        reject(err);
      };
    });
  }

  private async exchange2FAToken(exchangeToken: string): Promise<Session> {
    const response = await fetch(`${this.baseUrl}/v1/client/auth/2fa/exchange`, {
      method: "POST",
      headers: this.getHeaders(),
      credentials: "include",
      body: JSON.stringify({ exchangeToken }),
    });

    if (!response.ok) {
      throw new Error("Failed to exchange 2FA token");
    }

    const data = await response.json();
    this.setSession(data.session);
    return data.session;
  }

  async refreshSession(): Promise<Session | null> {
    const response = await fetch(`${this.baseUrl}/oauth/token`, {
      method: "POST",
      headers: this.getHeaders(),
      credentials: "include",
      body: JSON.stringify({ grant_type: "refresh_token" }),
    });

    if (!response.ok) {
      this.setSession(null);
      return null;
    }

    const data = await response.json();
    this.setSession(data.session);
    return data.session;
  }

  /**
   * Subscribes to auth state changes.
   * Triggers on: (a) Initial load, (b) Login/Signup success, (c) Silent refresh success, 
   * (d) Silent refresh failure/revocation (flips user to null), (e) Sign out.
   */
  onAuthStateChanged(callback: AuthStateCallback): () => void {
    this.stateListeners.add(callback);
    callback(this.currentSession?.user || null, this.currentSession);

    return () => {
      this.stateListeners.delete(callback);
    };
  }

  private setSession(session: Session | null) {
    this.currentSession = session;
    if (this.refreshTimer) {
      clearTimeout(this.refreshTimer);
      this.refreshTimer = null;
    }

    if (session && this.autoRefresh) {
      const expiresInMs = (session.expiresAt * 1000) - Date.now() - 60000;
      if (expiresInMs > 0) {
        this.refreshTimer = setTimeout(() => this.refreshSession(), expiresInMs);
      }
    }

    this.notifyListeners();
  }

  private notifyListeners() {
    const user = this.currentSession?.user || null;
    this.stateListeners.forEach((cb) => cb(user, this.currentSession));
  }

  async signOut(): Promise<void> {
    await fetch(`${this.baseUrl}/v1/client/auth/logout`, {
      method: "POST",
      headers: this.getHeaders(),
      credentials: "include",
    }).catch(() => {});

    this.setSession(null);
  }
}
