import { defineConfig } from "vitepress";

// https://vitepress.dev/reference/site-config
export default defineConfig({
  title: "> ada",
  description: "Go Web Library",
  head: [["link", { rel: "icon", href: "/assets/icon.png" }]],
  base: "/ada/",
  themeConfig: {
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
        ],
      },
    ],

    socialLinks: [{ icon: "github", link: "https://github.com/rakunlabs/ada" }],
  },
});
