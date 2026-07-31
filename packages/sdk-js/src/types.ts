export interface AuthnConfig {
  publishableKey: string;
  baseUrl?: string;
  clientType?: "web" | "native";
}

export interface User {
  id: string;
  email: string;
  emailVerified: boolean;
  name?: string;
  avatarUrl?: string;
}

export interface Session {
  accessToken: string;
  /**
   * refreshToken is returned in JSON for native mobile clients (Android/iOS).
   * For web clients, refreshToken is managed automatically via HttpOnly SameSite cookies.
   */
  refreshToken?: string;
  expiresAt: number;
  user: User;
}

export interface AuthResponse {
  session?: Session;
  requires2FA?: boolean;
  twoFactorToken?: string;
  error?: string;
}
