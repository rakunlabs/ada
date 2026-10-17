import { defineConfig } from "vitepress";
import { withMermaid } from "vitepress-plugin-mermaid";

// https://vitepress.dev/reference/site-config
export default withMermaid(defineConfig({
  title: "> ada",
  description: "Go Web Framework",
  head: [["link", { rel: "icon", href: "/ada/assets/favicon.ico" }]],
  base: "/ada/",
  ignoreDeadLinks: false,
  lastUpdated: true,
  markdown: {
    theme: {
      light: "monokai",
      dark: "monokai",
    },
  },
  themeConfig: {
    search: {
      provider: "local",
    },

    outline: {
      level: [2, 3],
    },

    editLink: {
      pattern: "https://github.com/rakunlabs/ada/edit/main/_docs/docs/:path",
      text: "Edit this page on GitHub",
    },

    // https://vitepress.dev/reference/default-theme-config
    nav: [
      { text: "Home", link: "/" },
      { text: "Guide", link: "/getting-started.md" },
    ],

    sidebar: [
      {
        text: "Getting Started",
        link: "/getting-started.md",
      },
      {
        text: "Guide",
        link: "/guide/",
        items: [
          {
            text: "Start Server",
            link: "/guide/start.md",
          },
          {
            text: "Routing",
            link: "/guide/routing.md",
          },
          {
            text: "Context",
            link: "/guide/context.md",
          },
          {
            text: "Binding",
            link: "/guide/binding.md",
          },
          {
            text: "Microservice",
            link: "/guide/microservice.md",
          },
        ],
      },
      {
        text: "Middleware",
        link: "/guide/middleware/",
        collapsed: false,
        items: [
          {
            text: "Recover",
            link: "/guide/middleware/recover.md",
          },
          {
            text: "Request ID",
            link: "/guide/middleware/request-id.md",
          },
          {
            text: "Log",
            link: "/guide/middleware/log.md",
          },
          {
            text: "Rate Limit",
            link: "/guide/middleware/ratelimit.md",
          },
          {
            text: "Body Limit",
            link: "/guide/middleware/bodylimit.md",
          },
          {
            text: "Timeout",
            link: "/guide/middleware/timeout.md",
          },
          {
            text: "CORS",
            link: "/guide/middleware/cors.md",
          },
          {
            text: "Telemetry",
            link: "/guide/middleware/telemetry.md",
          },
          {
            text: "Encoding",
            link: "/guide/middleware/encoding.md",
          },
          {
            text: "Server",
            link: "/guide/middleware/server.md",
          },
          {
            text: "ForwardAuth",
            link: "/guide/middleware/forwardauth.md",
          },
          {
            text: "Auth",
            link: "/guide/middleware/auth/",
            collapsed: true,
            items: [
              {
                text: "Strategies",
                link: "/guide/middleware/auth/strategies.md",
              },
              {
                text: "Resource Server",
                link: "/guide/middleware/auth/resource-server.md",
              },
              {
                text: "Configuration",
                link: "/guide/middleware/auth/configuration.md",
              },
              {
                text: "Identity & Access",
                link: "/guide/middleware/auth/access.md",
              },
              {
                text: "Sessions",
                link: "/guide/middleware/auth/sessions.md",
              },
              {
                text: "Login UI",
                link: "/guide/middleware/auth/login-ui.md",
              },
            ],
          },
        ],
      },
      {
        text: "Handler",
        collapsed: false,
        items: [
          {
            text: "Folder",
            link: "/guide/handler/folder.md",
          },
          {
            text: "Swagger",
            link: "/guide/handler/swagger.md",
          },
        ],
      },
      {
        text: "Advanced",
        collapsed: false,
        items: [
          {
            text: "Runtime Reload",
            link: "/guide/runtime-reload.md",
          },
          {
            text: "Performance",
            link: "/guide/performance.md",
          },
          {
            text: "Security Migration",
            link: "/guide/security-migration.md",
          },
        ],
      },
    ],

    socialLinks: [{ icon: "github", link: "https://github.com/rakunlabs/ada" }],
  },
  mermaid: {},
  vite: {
    optimizeDeps: {
      include: ["mermaid", "dayjs"],
    },
  },
}));
