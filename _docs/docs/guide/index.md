---
next: false
---
# Guide

Learn how to use Ada with our comprehensive documentation.

<script setup>
const guides = [
  {
    icon: '📄',
    title: 'Routing',
    description: 'Learn how to handle HTTP requests and create powerful routing patterns',
    href: './routing'
  },
  {
    icon: '⚡',
    title: 'Middleware',
    description: 'Add powerful middleware functions to enhance your application',
    href: './middleware'
  },
  {
    icon: '🔌',
    title: 'Microservice',
    description: 'Build microservices with essential middleware and best practices',
    href: './microservice'
  },
  // {
  //   icon: '⚙️',
  //   title: 'Configuration',
  //   description: 'Configure your Ada application with environment variables and settings',
  //   href: './configuration'
  // },
  // {
  //   icon: '🔧',
  //   title: 'API Reference',
  //   description: 'Complete API documentation and examples',
  //   href: './api'
  // },
  // {
  //   icon: '🚀',
  //   title: 'Deployment',
  //   description: 'Deploy your Ada application to production',
  //   href: './deployment'
  // },
  // {
  //   icon: '🧪',
  //   title: 'Testing',
  //   description: 'Testing strategies and best practices',
  //   href: './testing'
  // }
]
</script>

<div :class="$style.container">
  <a
    v-for="guide in guides"
    :key="guide.title"
    :class="$style.card"
    :href="guide.href"
  >
    <h3 :class="$style.title">{{ guide.icon }} {{ guide.title }}</h3>
    <p :class="$style.description">{{ guide.description }}</p>
  </a>
</div>

<style module>
.container {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
  gap: 1rem;
  margin-top: 2rem;
}

.card {
  display: block;
  padding: 1.5rem;
  border: 1px solid var(--vp-c-text-3);
  border-radius: 8px;
  text-decoration: none !important;
  color: inherit !important;
  transition: all 0.2s ease;
}

.card:hover {
  border-color: var(--vp-c-text-1);
  box-shadow: 0 6px 16px rgba(0, 0, 0, 0.12);
  text-decoration: none !important;
  color: inherit !important;
}

.title {
  font-size: 1.125rem;
  font-weight: 600;
  margin: 0 0 0.5rem 0 !important;
  color: var(--vp-c-text-1) !important;
}

.description {
  font-size: 0.875rem;
  color: var(--vp-c-text-1) !important;
  margin: 0;
  line-height: 1.5;
}

@media (max-width: 768px) {
  .container {
    grid-template-columns: 1fr;
  }

  .card {
    padding: 1.25rem;
  }
}
</style>
