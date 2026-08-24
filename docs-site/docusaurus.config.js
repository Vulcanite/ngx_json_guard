const lightCodeTheme = require('prism-react-renderer').themes.github;
const darkCodeTheme = require('prism-react-renderer').themes.dracula;

/** @type {import('@docusaurus/types').Config} */
const config = {
  title: 'ngx_json_guard',
  tagline: 'Streaming JSON structural guard for NGINX — cheap admission before ModSecurity, never instead of it',
  url: 'https://vulcanite.github.io',
  baseUrl: '/ngx_json_guard/',
  onBrokenLinks: 'throw',
  onBrokenMarkdownLinks: 'warn',
  favicon: 'img/logo.svg',

  themes: ['@docusaurus/theme-mermaid'],
  markdown: {
    mermaid: true,
  },

  presets: [
    [
      'classic',
      /** @type {import('@docusaurus/preset-classic').Options} */
      {
        docs: {
          routeBasePath: '/',
          sidebarPath: require.resolve('./sidebars.js'),
        },
        blog: false,
        theme: {
          customCss: require.resolve('./src/css/custom.css'),
        },
      },
    ],
  ],

  themeConfig:
    /** @type {import('@docusaurus/preset-classic').ThemeConfig} */
    {
      navbar: {
        title: 'ngx_json_guard',
        logo: {
          alt: 'ngx_json_guard shield',
          src: 'img/logo.svg',
        },
        items: [
          { type: 'doc', docId: 'intro/why', label: 'Why' },
          { type: 'doc', docId: 'install/linux', label: 'Install (Linux)' },
          { type: 'doc', docId: 'install/docker', label: 'Install (Docker)' },
          { type: 'doc', docId: 'configuration/nginx', label: 'NGINX Config' },
          { type: 'doc', docId: 'comparison/engines', label: 'Comparison' },
          { type: 'doc', docId: 'performance/results', label: 'Performance' },
        ],
      },
      footer: {
        style: 'dark',
        links: [
          {
            title: 'Docs',
            items: [
              { label: 'Why it was built', to: '/' },
              { label: 'NGINX configuration', to: '/configuration/nginx' },
              { label: 'Engine comparison', to: '/comparison/engines' },
            ],
          },
          {
            title: 'More',
            items: [
              { label: 'Performance results', to: '/performance/results' },
            ],
          },
        ],
        copyright: `Built for NGINX operators who keep full WAF inspection enabled.`,
      },
      prism: {
        theme: lightCodeTheme,
        darkTheme: darkCodeTheme,
        additionalLanguages: ['c', 'bash', 'nginx', 'json'],
      },
      mermaid: {
        theme: {
          light: 'base',
          dark: 'dark',
        },
        options: {
          themeVariables: {
            primaryColor: '#eef4ff',
            primaryBorderColor: '#3b74d2',
            primaryTextColor: '#12233f',
            lineColor: '#5b7191',
            fontFamily: 'system-ui, sans-serif',
          },
        },
      },
    },
};

module.exports = config;
