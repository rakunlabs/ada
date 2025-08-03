import { defineConfig } from "vitepress";

// https://vitepress.dev/reference/site-config
export default defineConfig({
  title: "> ada",
  description: "Go Web Library",
  head: [["link", { rel: "icon", href: "/assets/icon.png" }]],
  base: "/ada/",
  
  // Configure syntax highlighting with Monokai theme
  markdown: {
    theme: {
      light: 'monokai',
      dark: 'monokai'
    },
    // lineNumbers: true
  },
  themeConfig: {
    search: {
      provider: 'local'
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
            text: "Routing",
            link: "/guide/routing.md",
          },
          {
            text: "Middleware",
            link: "/guide/middleware.md",
          },
        ],
      },
    ],

    socialLinks: [{ icon: "github", link: "https://github.com/rakunlabs/ada" }],
  },
});
