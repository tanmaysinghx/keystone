/**
 * User claims parsed from OpenID Connect ID token and Access token.
 */
export interface PortalUser {
  id: string;
  email: string;
  name: string;
  roles: string[];
  rawClaims?: Record<string, any>;
}

/**
 * Active authentication session containing tokens and expiration metadata.
 */
export interface PortalSession {
  user: PortalUser;
  accessToken: string;
  idToken: string;
  refreshToken?: string;
  expiresIn?: number;
  expiresAt: number;
}

/**
 * Configuration options for initializing PortalSSO.
 */
export interface PortalSSOConfig {
  /**
   * The base URL of your Portal SSO deployment.
   * e.g. "https://portal.tanmaysinghx.com"
   */
  portalUrl: string;

  /**
   * The public OAuth 2.1 client ID registered in Portal SSO.
   * e.g. "eggless-observability"
   */
  clientId: string;

  /**
   * The OAuth 2.1 redirect URI.
   * Defaults to `${portalUrl}/oauth2/popup-callback` for zero-boilerplate popup login.
   */
  redirectUri?: string;

  /**
   * Requested OAuth scopes separated by spaces.
   * Defaults to "openid profile email".
   */
  scope?: string;

  /**
   * Key used for caching session in localStorage.
   * Defaults to "portal_sso_session".
   */
  storageKey?: string;
}

/**
 * Options for popup login window dimensions.
 */
export interface PopupOptions {
  width?: number;
  height?: number;
}

/**
 * Callback function for auth state changes.
 */
export type AuthStateCallback = (user: PortalUser | null) => void;
