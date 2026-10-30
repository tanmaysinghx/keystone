# Portal SSO SDK snapshot

Unmodified `src/`, `README.md` and `tsconfig.json` from the local Portal SSO repository, commit `324082b6cb644b5cc8e7687e192559e0737b83b4`, package `@tanmaysinghx/portal-sso` (Apache-2.0, Tanmay Singh).

The npm 1.0.0 release does not yet expose `getAccessTokenAsync`; the checked-in upstream SDK includes rotating refresh token support. Keystone vendors this source so a clean checkout does not depend on a sibling repository. Only package/build metadata differs. Replace this local package with the official npm release when its refresh API is published. No Portal server source or credentials are copied.
