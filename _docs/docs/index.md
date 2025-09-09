---
# https://vitepress.dev/reference/default-theme-home-page
layout: home

hero:
  # name: "ada"
  text: "Go Web Framework"
  # tagline: documentation
  image:
    src: /assets/ada.png
    alt: ada
  actions:
    - theme: brand
      text: Getting Started
      link: /getting-started.md
    - theme: alt
      text: Guide
      link: /guide.md

features:
  - title: Simple Mux
    details: Path parameter and wildcard support without method
  - title: Std Compatible
    details: Compatible with net/http handlers and middlewares
  - title: Helpful functions
    details: All you need utility functions
---
