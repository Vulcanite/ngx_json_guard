/** @type {import('@docusaurus/plugin-content-docs').SidebarsConfig} */
module.exports = {
  tutorialSidebar: [
    {
      type: 'category',
      label: 'Getting started',
      items: ['intro/why', 'intro/architecture'],
    },
    {
      type: 'category',
      label: 'Installation',
      items: ['install/linux', 'install/docker'],
    },
    {
      type: 'category',
      label: 'Configuration',
      items: ['configuration/nginx'],
    },
    {
      type: 'category',
      label: 'Evidence',
      items: ['comparison/engines', 'performance/results'],
    },
  ],
};
