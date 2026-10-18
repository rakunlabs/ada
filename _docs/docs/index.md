---
# https://vitepress.dev/reference/default-theme-home-page
layout: home

hero:
  text: "Go Web Framework"
  tagline: "A net/http compatible mux with batteries-included middleware, built-in auth, and runtime reload."
  image:
    src: /assets/ada.png
    alt: ada
  actions:
    - theme: brand
      text: Getting Started
      link: /getting-started.md
    - theme: alt
      text: Guide
      link: /guide/
    - theme: alt
      text: GitHub
      link: https://github.com/rakunlabs/ada

features:
  - icon:
      src: /assets/thread/signpost.svg
      width: 44
      height: 44
    title: Simple Mux
    details: Static, parameter, and wildcard routes with backtracking. Path matching is method-agnostic.
    link: /guide/routing
  - icon:
      src: /assets/thread/puzzle.svg
      width: 44
      height: 44
    title: Std Compatible
    details: Plain net/http handlers and middlewares work as-is, alongside ada.Context handlers.
    link: /guide/context
  - icon:
      src: /assets/thread/layers.svg
      width: 44
      height: 44
    title: Middleware Set
    details: Recover, log, CORS, CSRF, rate limit, body limit, timeout, telemetry, encoding, and more.
    link: /guide/middleware/
  - icon:
      src: /assets/thread/padlock.svg
      width: 44
      height: 44
    title: Built-in Auth
    details: OAuth2/OIDC, passkeys, LDAP, magic links, MFA, sessions, and a login UI.
    link: /guide/middleware/auth/
  - icon:
      src: /assets/thread/reload.svg
      width: 44
      height: 44
    title: Runtime Reload
    details: Swap, disable, or add middlewares while the server is running, with no restart.
    link: /guide/runtime-reload
  - icon:
      src: /assets/thread/feather.svg
      width: 44
      height: 44
    title: Low Overhead
    details: Zero heap allocations on the request hot path, with benchmarks against Echo and Gin.
    link: /guide/performance
---
