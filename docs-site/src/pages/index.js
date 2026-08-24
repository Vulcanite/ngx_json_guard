import React from 'react';
import clsx from 'clsx';
import Link from '@docusaurus/Link';
import useDocusaurusContext from '@docusaurus/useDocusaurusContext';
import useBaseUrl from '@docusaurus/useBaseUrl';
import Mermaid from '@theme/Mermaid';
import Layout from '@theme/Layout';

import styles from './index.module.css';

const ARCH_DIAGRAM = `flowchart LR
    C([Client]) --> N[NGINX reads / spools body]
    N --> G{json_guard<br/>structural check}
    G -- "malformed → 400" --> X1([Rejected at the edge])
    G -- "over limit → 413" --> X2([Rejected at the edge])
    G -- "valid structure" --> M[ModSecurity + CRS<br/>full inspection]
    M -- "attack found → 403" --> X3([Blocked])
    M -- "clean → 200" --> U([Upstream app])
    style G fill:#2e6db5,stroke:#173d75,color:#ffffff,stroke-width:2px
    style M fill:#b96a20,stroke:#7d4a13,color:#ffffff,stroke-width:2px
    style C fill:#2f8f4e,stroke:#1c5c31,color:#ffffff
    style U fill:#2f8f4e,stroke:#1c5c31,color:#ffffff
    style X1 fill:#c0392b,stroke:#7d241a,color:#ffffff
    style X2 fill:#c0392b,stroke:#7d241a,color:#ffffff
    style X3 fill:#c0392b,stroke:#7d241a,color:#ffffff`;

const STATS = [
  { value: '0.67%', label: 'added latency on an accepted 20 MiB body under full CRS' },
  { value: '~10 µs', label: 'guard cost on a typical small JSON body' },
  { value: '260 MiB/s', label: 'single-threaded streaming parse throughput' },
  { value: '11 / 11', label: 'structural violation classes rejected (ModSecurity: 7, Coraza: 6)' },
];

const FEATURES = [
  {
    title: 'Structural admission, not detection',
    body: (
      <>
        Well-formedness plus configurable limits — depth, key/string/number
        lengths, token counts, object and array widths. Malformed JSON gets
        a <b>400</b>, structurally abusive JSON a <b>413</b>. Ten NGINX
        directives, sane defaults.
      </>
    ),
  },
  {
    title: 'The body survives, bit-for-bit',
    body: (
      <>
        Validation is read-only over NGINX&apos;s own request-body buffers
        and temp files. ModSecurity still inspects <b>every byte</b> —
        an SQLi planted at the tail of a 20 MiB document is still blocked,
        verified by SHA-256 digests at the upstream.
      </>
    ),
  },
  {
    title: 'Streaming, bounded memory',
    body: (
      <>
        A non-recursive finite state machine walks the body in 64 KiB
        chunks with a fixed ~96 KiB parser state. No DOM, no body
        retention — memory is O(depth), never O(body size).
      </>
    ),
  },
  {
    title: 'Runs before your WAF',
    body: (
      <>
        A PREACCESS layer in front of ModSecurity + CRS or Coraza — so you
        can keep <b>full</b> body inspection enabled and drop partial
        processing, instead of choosing between safety and coverage.
      </>
    ),
  },
];

const QUICK_START = `load_module modules/ngx_http_json_guard_module.so;

location /api/ {
    json_guard on;          # that's it — defaults are sane
    proxy_pass http://app;
}`;

export default function Home() {
  const { siteConfig } = useDocusaurusContext();
  return (
    <Layout
      title={`${siteConfig.title} — JSON structural guard for NGINX`}
      description="Streaming JSON structural validation for NGINX. Cheap admission before ModSecurity, never instead of it.">
      <header className={clsx('hero hero--primary', styles.heroBanner)}>
        <div className="container">
          <img
            src={useBaseUrl('img/logo.svg')}
            alt="ngx_json_guard shield"
            className={styles.heroLogo}
            width="88"
            height="88"
          />
          <h1 className="hero__title">{siteConfig.title}</h1>
          <p className={clsx('hero__subtitle', styles.heroSubtitle)}>
            Streaming JSON structural guard for NGINX.
            <br />
            Cheap admission <b>before</b> ModSecurity — never instead of it.
          </p>
          <div className={styles.buttons}>
            <Link
              className="button button--secondary button--lg"
              to={useBaseUrl('/docs/install/linux')}>
              Get started (Linux) · 5 min
            </Link>
            <Link
              className="button button--secondary button--lg"
              to={useBaseUrl('/docs/install/docker')}>
              Run in Docker
            </Link>
            <Link
              className="button button--outline button--lg"
              to={useBaseUrl('/docs/performance/results')}>
              Benchmarks
            </Link>
          </div>
        </div>
      </header>

      <main>
        <section className={styles.statsSection}>
          <div className="container">
            <div className="row">
              {STATS.map((s, i) => (
                <div key={i} className="col col--3">
                  <div className={clsx('text--center', styles.statCard)}>
                    <div className={styles.statValue}>{s.value}</div>
                    <div className={styles.statLabel}>{s.label}</div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </section>

        <section className={styles.section}>
          <div className="container">
            <h2 className={clsx('text--center', styles.sectionTitle)}>
              Where it sits
            </h2>
            <p className={clsx('text--center', styles.sectionLead)}>
              The guard answers one narrow question before anything
              expensive runs: <i>is this well-formed JSON with a sane
              structure?</i> Content inspection stays where it belongs.
            </p>
            <div className={styles.diagramWrap}>
              <Mermaid chart={ARCH_DIAGRAM} />
            </div>
          </div>
        </section>

        <section className={styles.sectionAlt}>
          <div className="container">
            <h2 className={clsx('text--center', styles.sectionTitle)}>
              What you get
            </h2>
            <div className="row" style={{ marginTop: '2rem' }}>
              {FEATURES.map((f, i) => (
                <div key={i} className="col col--6" style={{ padding: '0.75rem' }}>
                  <div className={styles.featureCard}>
                    <h3>{f.title}</h3>
                    <p>{f.body}</p>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </section>

        <section className={styles.section}>
          <div className="container text--center">
            <h2 className={styles.sectionTitle}>Quick start</h2>
            <div className={styles.codeWrap}>
              <pre className={styles.codeBlock}>
                <code>{QUICK_START}</code>
              </pre>
            </div>
            <p className={styles.sectionLead}>
              Not a WAF. No signatures, no CRS rules, no SQLi or XSS
              detection — those stay in ModSecurity.
            </p>
            <Link
              className="button button--primary button--lg"
              to={useBaseUrl('/docs/')}>
              Why it was built
            </Link>
          </div>
        </section>
      </main>
    </Layout>
  );
}
