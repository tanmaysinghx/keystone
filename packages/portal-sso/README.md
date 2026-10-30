# @tanmaysinghx/portal-sso

Official lightweight client SDK and drop-in UI button for **Portal SSO** (OAuth 2.1 & OpenID Connect).

- **Okta-style Popup Login**: Authenticates in a centered modal and resolves seamlessly—no app reloads or lost state.
- **Zero Callback Hosting**: Uses the built-in `https://<portal-url>/oauth2/popup-callback` relay.
- **Framework Agnostic**: Works out of the box in **React, Angular, Vue, Svelte, Next.js, and Vanilla JavaScript**.
- **Drop-in UI Button**: Includes `<portal-login-button>` custom element with dark/light themes and loading spinner.
- **Security by Default**: Strict OAuth 2.1 + PKCE (S256) WebCrypto validation. Zero external dependencies.

---

## Installation

```bash
npm install @tanmaysinghx/portal-sso
```

---

## 1. Quickstart: 3-Line Drop-in Button (Any Framework)

Import the package once in your app's root entry file (`main.ts`, `index.tsx`, or `App.vue`):

```ts
import '@tanmaysinghx/portal-sso';
```

Now you can drop `<portal-login-button>` directly into your HTML / JSX / Angular template:

```html
<portal-login-button
  portal-url="https://portal.tanmaysinghx.com"
  client-id="eggless-observability"
  theme="dark"
  label="Sign in with Portal SSO">
</portal-login-button>

<script>
  // Listen for successful login
  document.querySelector('portal-login-button').addEventListener('login-success', (e) => {
    const { user, session } = e.detail;
    console.log('Logged in user:', user.name, user.email);
    console.log('Access token:', session.accessToken);
  });
</script>
```

---

## 2. Framework Usage

### React / Next.js

```tsx
import { useState, useEffect } from 'react';
import { PortalSSO, PortalUser } from '@tanmaysinghx/portal-sso';

const sso = new PortalSSO({
  portalUrl: 'https://portal.tanmaysinghx.com',
  clientId: 'eggless-observability',
});

export function Login() {
  const [user, setUser] = useState<PortalUser | null>(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    setUser(sso.getCurrentUser());
  }, []);

  const handleLogin = async () => {
    setLoading(true);
    try {
      const session = await sso.loginWithPopup();
      setUser(session.user);
    } catch (err: any) {
      alert('Login failed: ' + err.message);
    } finally {
      setLoading(false);
    }
  };

  if (user) {
    return (
      <div>
        <p>Welcome, {user.name} ({user.email})</p>
        <button onClick={() => { sso.logout(); setUser(null); }}>Sign Out</button>
      </div>
    );
  }

  return (
    <button onClick={handleLogin} disabled={loading}>
      {loading ? 'Connecting...' : 'Sign In with Portal SSO'}
    </button>
  );
}
```

---

### Angular (Standalone Component)

```typescript
import { Component, signal } from '@angular/core';
import { PortalSSO, PortalUser } from '@tanmaysinghx/portal-sso';

@Component({
  selector: 'app-navbar',
  standalone: true,
  template: `
    @if (user()) {
      <span>Hello, {{ user()?.name }}</span>
      <button (click)="logout()">Sign Out</button>
    } @else {
      <button (click)="login()">Sign in with Portal SSO</button>
    }
  `
})
export class NavbarComponent {
  private sso = new PortalSSO({
    portalUrl: 'https://portal.tanmaysinghx.com',
    clientId: 'eggless-observability',
  });

  readonly user = signal<PortalUser | null>(this.sso.getCurrentUser());

  async login() {
    try {
      const session = await this.sso.loginWithPopup();
      this.user.set(session.user);
    } catch (err: any) {
      console.error('Sign-in cancelled:', err);
    }
  }

  logout() {
    this.sso.logout();
    this.user.set(null);
  }
}
```

---

### Vue 3 / Nuxt

```vue
<script setup lang="ts">
import { ref, onMounted } from 'vue';
import { PortalSSO, PortalUser } from '@tanmaysinghx/portal-sso';

const sso = new PortalSSO({
  portalUrl: 'https://portal.tanmaysinghx.com',
  clientId: 'eggless-observability',
});

const user = ref<PortalUser | null>(null);

onMounted(() => {
  user.value = sso.getCurrentUser();
});

async function login() {
  const session = await sso.loginWithPopup();
  user.value = session.user;
}

function logout() {
  sso.logout();
  user.value = null;
}
</script>

<template>
  <div v-if="user">
    <p>Signed in as {{ user.email }}</p>
    <button @click="logout">Logout</button>
  </div>
  <button v-else @click="login">Sign in with Portal SSO</button>
</template>
```

---

## 3. Full API Reference

### `new PortalSSO(config)`
```typescript
interface PortalSSOConfig {
  portalUrl: string;    // e.g. 'https://portal.tanmaysinghx.com'
  clientId: string;     // Your OAuth 2.1 client ID
  scope?: string;       // Default: 'openid profile email'
  redirectUri?: string; // Default: `${portalUrl}/oauth2/popup-callback`
  storageKey?: string;  // Default: 'portal_sso_session'
}
```

### Methods
- `loginWithPopup(options?: { width?: number; height?: number }): Promise<PortalSession>`  
  Opens centered popup window and returns user claims and tokens.
- `getCurrentUser(): PortalUser | null`  
  Retrieves authenticated user from local storage (auto-verifies expiration).
- `getSession(): PortalSession | null`  
  Retrieves active session object with access/id tokens.
- `getAccessToken(): string | null`  
  Synchronous cached token accessor. Use `getAccessTokenAsync()` for API calls that must refresh first.
- `getAccessTokenAsync(): Promise<string | null>`
  Returns a usable access token, refreshing it when it is within 60 seconds of expiry.
- `getSessionAsync(): Promise<PortalSession | null>`
  Returns a session with a usable access token, refreshing it when needed.
- `refreshSession(): Promise<PortalSession | null>`
  Forces a refresh now and saves the rotated refresh token.
- `logout(): void`  
  Clears local storage session and notifies listeners.
- `onAuthStateChange(callback: (user: PortalUser | null) => void): () => void`  
  Subscribes to login, logout, and token expiry events.
- `loginWithRedirect(redirectUri?: string): Promise<void>`  
  Triggers standard full-page browser redirect.
- `handleRedirectCallback(): Promise<PortalSession | null>`  
  Handles authorization code exchange after full-page redirect.

---

## License

Apache-2.0
