import { PortalSSO } from './index';
import type { PortalSession, PortalUser } from './types';

const LOGO_SVG = `
<svg width="20" height="20" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
  <path d="M12 2L4 7V17L12 22L20 17V7L12 2Z" fill="url(#portal_grad)" stroke="#ea580c" stroke-width="1.5" stroke-linejoin="round"/>
  <path d="M12 6L16 9.5V14.5L12 18L8 14.5V9.5L12 6Z" fill="#ffffff" fill-opacity="0.9"/>
  <defs>
    <linearGradient id="portal_grad" x1="4" y1="2" x2="20" y2="22" gradientUnits="userSpaceOnUse">
      <stop stop-color="#f59e0b"/>
      <stop offset="1" stop-color="#ea580c"/>
    </linearGradient>
  </defs>
</svg>
`;

/**
 * Standard Web Component (<portal-login-button>) providing a ready-to-use
 * sign-in button that works natively in Angular, React, Vue, Svelte, and plain HTML.
 */
export class PortalLoginButtonElement extends HTMLElement {
  private button: HTMLButtonElement | null = null;
  private ssoInstance: PortalSSO | null = null;
  private isLoading = false;

  static get observedAttributes() {
    return ['portal-url', 'client-id', 'label', 'theme', 'scope'];
  }

  connectedCallback() {
    this.render();
  }

  attributeChangedCallback() {
    this.initSSO();
    this.updateButtonContent();
  }

  private initSSO() {
    const portalUrl = this.getAttribute('portal-url') || window.location.origin;
    const clientId = this.getAttribute('client-id') || '';
    const scope = this.getAttribute('scope') || 'openid profile email';

    if (clientId) {
      this.ssoInstance = new PortalSSO({
        portalUrl,
        clientId,
        scope,
      });
    }
  }

  private render() {
    const shadow = this.attachShadow({ mode: 'open' });
    const theme = this.getAttribute('theme') || 'dark';

    const style = document.createElement('style');
    style.textContent = `
      :host {
        display: inline-block;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      }
      .portal-btn {
        display: inline-flex;
        align-items: center;
        justify-content: center;
        gap: 0.6rem;
        padding: 0.625rem 1.125rem;
        font-size: 0.875rem;
        font-weight: 600;
        line-height: 1;
        border-radius: 0.5rem;
        cursor: pointer;
        transition: all 0.15s ease-in-out;
        user-select: none;
        outline: none;
        text-decoration: none;
        box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
      }
      .portal-btn:disabled {
        opacity: 0.65;
        cursor: not-allowed;
      }
      .portal-btn.dark {
        background-color: #18181b;
        color: #ffffff;
        border: 1px solid #27272a;
      }
      .portal-btn.dark:hover:not(:disabled) {
        background-color: #27272a;
        border-color: #3f3f46;
      }
      .portal-btn.light {
        background-color: #ffffff;
        color: #09090b;
        border: 1px solid #e4e4e7;
      }
      .portal-btn.light:hover:not(:disabled) {
        background-color: #f4f4f5;
        border-color: #d4d4d8;
      }
      .portal-btn:focus-visible {
        box-shadow: 0 0 0 3px rgba(245, 158, 11, 0.4);
      }
      .spinner {
        width: 16px;
        height: 16px;
        border: 2px solid rgba(255, 255, 255, 0.2);
        border-top-color: #f59e0b;
        border-radius: 50%;
        animation: spin 0.8s linear infinite;
      }
      @keyframes spin {
        to { transform: rotate(360deg); }
      }
    `;

    this.button = document.createElement('button');
    this.button.type = 'button';
    this.button.className = `portal-btn ${theme}`;
    this.button.addEventListener('click', () => this.handleClick());

    shadow.appendChild(style);
    shadow.appendChild(this.button);

    this.initSSO();
    this.updateButtonContent();
  }

  private updateButtonContent() {
    if (!this.button) return;
    const label = this.getAttribute('label') || 'Sign in with Portal SSO';

    if (this.isLoading) {
      this.button.disabled = true;
      this.button.innerHTML = `<span class="spinner"></span><span>Connecting...</span>`;
    } else {
      this.button.disabled = false;
      this.button.innerHTML = `${LOGO_SVG}<span>${label}</span>`;
    }
  }

  private async handleClick() {
    if (!this.ssoInstance) {
      console.error('[PortalSSO] Missing required client-id attribute on <portal-login-button>');
      return;
    }

    this.isLoading = true;
    this.updateButtonContent();

    try {
      const session = await this.ssoInstance.loginWithPopup();
      this.dispatchEvent(
        new CustomEvent<{ user: PortalUser; session: PortalSession }>('login-success', {
          bubbles: true,
          composed: true,
          detail: { user: session.user, session },
        })
      );
    } catch (err: any) {
      this.dispatchEvent(
        new CustomEvent<{ error: Error }>('login-error', {
          bubbles: true,
          composed: true,
          detail: { error: err },
        })
      );
    } finally {
      this.isLoading = false;
      this.updateButtonContent();
    }
  }
}

/**
 * Registers the <portal-login-button> custom element in the DOM if in browser environment.
 */
export function registerPortalButton() {
  if (typeof window !== 'undefined' && 'customElements' in window) {
    if (!customElements.get('portal-login-button')) {
      customElements.define('portal-login-button', PortalLoginButtonElement);
    }
  }
}
