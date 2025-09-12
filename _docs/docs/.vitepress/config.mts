import { defineConfig } from "vitepress";

// https://vitepress.dev/reference/site-config
export default defineConfig({
  title: "> ada",
  description: "Go Web Framework",
  head: [["link", { rel: "icon", href: "/ada/assets/favicon.ico" }]],
  base: "/ada/",
  // Configure syntax highlighting with Monokai theme
  markdown: {
    theme: {
      light: "monokai",
      dark: "monokai",
    },
    // lineNumbers: true
  },
  themeConfig: {
    search: {
      provider: "local",
    },

    // https://vitepress.dev/reference/default-theme-config
    nav: [
      { text: "Home", link: "/" },
      { text: "Documents", link: "/getting-started.md" },
    ],

    sidebar: [
      {
        text: "Getting Started",
        link: "/getting-started.md",
      },
      {
        text: "Guide",
        link: "/guide.md",
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
            text: "Middleware",
            link: "/guide/middleware.md",
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
                text: "Cors",
                link: "/guide/middleware/cors.md",
              },
              {
                text: "Telemetry",
                link: "/guide/middleware/telemetry.md",
              },
            ],
          },
          {
            text: "Handler",
            items: [
              {
                text: "Folder",
                link: "/guide/handler/folder.md",
              },
              {
                text: "Swagger",
                link: "/guide/handler/swagger.md",
              }
            ],
          },
          {
            text: "Microservice",
            link: "/guide/microservice.md",
          },
        ],
      },
    ],

    socialLinks: [{ icon: "github", link: "https://github.com/rakunlabs/ada" }],
  },
});
