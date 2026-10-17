---
next: false
---
# Guide

Learn how to use Ada with our comprehensive documentation.

<script setup>
const sections = [
  {
    title: 'Basics',
    guides: [
      { title: 'Start Server', description: 'Start, stop, and gracefully shut down the server', href: './start' },
      { title: 'Routing', description: 'Static, parameter, and wildcard routes, groups, and matching rules', href: './routing' },
      { title: 'Context', description: 'ada.Context handlers, responses, and error handling', href: './context' },
      { title: 'Binding', description: 'Bind path, query, header, and body data to structs', href: './binding' },
      { title: 'Microservice', description: 'A ready-to-use middleware stack for services', href: './microservice' },
    ],
  },
  {
    title: 'Middleware & Handlers',
    guides: [
      { title: 'Middleware', description: 'Ordering, custom middleware, and every bundled middleware', href: './middleware/' },
      { title: 'Auth', description: 'Strategies, sessions, MFA, authorization, and the login UI', href: './middleware/auth/' },
      { title: 'Folder', description: 'Serve static files and SPAs from disk or embed.FS', href: './handler/folder' },
      { title: 'Swagger', description: 'Serve Swagger UI and generated API docs', href: './handler/swagger' },
    ],
  },
  {
    title: 'Advanced',
    guides: [
      { title: 'Runtime Reload', description: 'Replace, disable, and add middlewares while running', href: './runtime-reload' },
      { title: 'Performance', description: 'Benchmarks against Echo and Gin', href: './performance' },
      { title: 'Security Migration', description: 'Trusted proxies, authentication, CORS, and request limits', href: './security-migration' },
    ],
  },
]
</script>

<section v-for="section in sections" :key="section.title" :class="$style.section">
  <h2 :id="section.title.toLowerCase().replace(/[^a-z]+/g, '-')" :class="$style.heading">{{ section.title }}</h2>
  <div :class="$style.grid">
    <a
      v-for="guide in section.guides"
      :key="guide.title"
      :class="$style.card"
      :href="guide.href"
    >
      <span :class="$style.title">{{ guide.title }}</span>
      <span :class="$style.description">{{ guide.description }}</span>
    </a>
  </div>
</section>

<style module>
.section {
  margin-top: 2.5rem;
}

.heading {
  margin: 0 0 1rem !important;
  padding-top: 0 !important;
  border-top: none !important;
  font-size: 0.8125rem !important;
  font-weight: 600;
  letter-spacing: 0.06em;
  text-transform: uppercase;
  color: var(--vp-c-text-2);
}

.grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(240px, 1fr));
  gap: 0.75rem;
}

.card {
  display: flex;
  flex-direction: column;
  gap: 0.375rem;
  padding: 1rem 1.25rem;
  border: 1px solid var(--vp-c-divider);
  border-radius: 8px;
  background-color: var(--vp-c-bg-soft);
  text-decoration: none !important;
  color: inherit !important;
  transition: border-color 0.2s ease, background-color 0.2s ease;
}

.card:hover {
  border-color: var(--vp-c-brand-1);
}

.card:focus-visible {
  outline: 2px solid var(--vp-c-brand-1);
  outline-offset: 2px;
}

.title {
  font-size: 1rem;
  font-weight: 600;
  line-height: 1.4;
  color: var(--vp-c-text-1);
}

.card:hover .title {
  color: var(--vp-c-brand-1);
}

.description {
  font-size: 0.875rem;
  line-height: 1.5;
  color: var(--vp-c-text-2);
}
</style>
