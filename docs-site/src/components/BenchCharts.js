import React from 'react';
import clsx from 'clsx';
import styles from './BenchCharts.module.css';

/*
 * Benchmark charts for the docs. Plain HTML/CSS bars: no chart library,
 * no network requests, theme colors from Docusaurus CSS variables.
 *
 * Every value below is copied from a published table. Each dataset names
 * its source; do not round beyond what the source prints, and do not add a
 * value that has no source line. The tables on the pages stay the primary,
 * accessible form; these charts only supplement them.
 */

/* BENCHMARK.md lines 93-96 (section 1, parser micro-throughput). */
export const PARSER_THROUGHPUT = [
  { label: '100 KiB', value: 260 },
  { label: '1 MiB', value: 271 },
  { label: '10 MiB', value: 265 },
  { label: '20 MiB', value: 264 },
];

/* BENCHMARK.md lines 115, 117-119 (section 2, "Guard p50" column). */
export const GUARD_INSPECTION_P50 = [
  { label: 'Small JSON object (~100 B)', value: 0.01 },
  { label: '1 MiB clean JSON', value: 4.1 },
  { label: '20 MiB clean JSON', value: 96.3 },
  { label: '20 MiB, SQLi at tail', value: 82.9 },
];

/* BENCHMARK.md lines 168-172 (section 3, processor suites, MiB/s column). */
export const PROCESSOR_THROUGHPUT = [
  { label: 'Baseline (no JSON processing)', value: 127.2, tone: 'baseline' },
  { label: 'JSON Guard', value: 167.2, tone: 'guard' },
  { label: 'ModSecurity processor', value: 74.8, tone: 'modsec' },
  { label: 'Guard + ModSecurity processor', value: 105.8, tone: 'combo' },
  { label: 'Coraza processor', value: 55.7, tone: 'coraza' },
];

/* BENCHMARK.md lines 148-151 ("Early rejection economics"). */
export const OUTCOME_LATENCY = [
  { label: 'Clean, accepted (200, full CRS scan)', value: 2920, tone: 'modsec' },
  { label: 'SQLi at tail (403 by CRS)', value: 2031, tone: 'modsec' },
  { label: 'Malformed tail (400 by guard)', value: 313, tone: 'guard' },
  { label: 'Over limit (413 by guard)', value: 241, tone: 'guard' },
];

/*
 * Count of 400/413 cells per column in the structural validation matrix
 * (docs-site/docs/comparison/engines.mdx), cross-checked per case against
 * artifacts/cross-waf/20260824-004254/<engine>/correctness-w1/results.csv.
 */
export const CLASSES_CAUGHT = [
  { label: 'Baseline', value: 0, tone: 'baseline' },
  { label: 'JSON Guard', value: 11, tone: 'guard' },
  { label: 'ModSecurity', value: 6, tone: 'modsec' },
  { label: 'Coraza', value: 5, tone: 'coraza' },
];

/*
 * artifacts/cross-waf/20260824-004254/COMPARISON.md lines 54-56
 * ("Processor-Only Case Medians", columns blob_20m, malformed_tail_20m,
 * records_20m), rounded to whole ms as on the engines page. The 323 / 542
 * malformed-tail pair is also in BENCHMARK.md lines 153-155.
 */
export const REJECTION_COST = [
  {
    label: 'Clean 20 MiB, accepted',
    items: [
      { label: 'JSON Guard', value: 476, tone: 'guard' },
      { label: 'ModSecurity alone', value: 696, tone: 'modsec' },
      { label: 'Guard + ModSecurity', value: 829, tone: 'combo' },
    ],
  },
  {
    label: 'Malformed tail 20 MiB, rejected',
    items: [
      { label: 'JSON Guard', value: 395, tone: 'guard' },
      { label: 'ModSecurity alone', value: 542, tone: 'modsec' },
      { label: 'Guard + ModSecurity', value: 323, tone: 'combo' },
    ],
  },
  {
    label: 'High-cardinality 20 MiB, accepted',
    items: [
      { label: 'JSON Guard', value: 294, tone: 'guard' },
      { label: 'ModSecurity alone', value: 515, tone: 'modsec' },
      { label: 'Guard + ModSecurity', value: 519, tone: 'combo' },
    ],
  },
];

const defaultFormat = (v) => v.toLocaleString('en-US');

function Row({ item, max, unit, format }) {
  const pct = max > 0 ? (item.value / max) * 100 : 0;
  return (
    <li className={styles.row}>
      <span className={styles.label}>{item.label}</span>
      <span className={styles.track} aria-hidden="true">
        <span
          className={clsx(styles.bar, styles[`tone_${item.tone || 'guard'}`])}
          style={{ width: `${pct}%` }}
        />
      </span>
      <span className={styles.value}>
        {format(item.value)}
        {unit ? <span className={styles.unit}> {unit}</span> : null}
      </span>
    </li>
  );
}

/**
 * Horizontal bar chart. Pass `items` for one series, or `groups`
 * ([{label, items}]) for several small series sharing one scale.
 * `max` fixes the scale (e.g. 11 for "classes of 11"); otherwise the
 * largest value fills the track.
 */
export default function BarChart({
  title,
  unit,
  items,
  groups,
  max,
  caption,
  format = defaultFormat,
}) {
  const all = groups ? groups.flatMap((g) => g.items) : items;
  const scale = max ?? Math.max(...all.map((i) => i.value));
  const legend = groups
    ? groups[0].items.map((i) => ({ label: i.label, tone: i.tone }))
    : null;

  return (
    <figure className={styles.figure}>
      <div className={styles.title}>{title}</div>
      {legend ? (
        <ul className={styles.legend} aria-hidden="true">
          {legend.map((l) => (
            <li key={l.label}>
              <span className={clsx(styles.swatch, styles[`tone_${l.tone}`])} />
              {l.label}
            </li>
          ))}
        </ul>
      ) : null}
      {groups ? (
        groups.map((g) => (
          <div key={g.label} className={styles.group}>
            <div className={styles.groupLabel}>{g.label}</div>
            <ul className={styles.rows}>
              {g.items.map((item) => (
                <Row
                  key={item.label}
                  item={item}
                  max={scale}
                  unit={unit}
                  format={format}
                />
              ))}
            </ul>
          </div>
        ))
      ) : (
        <ul className={styles.rows}>
          {items.map((item) => (
            <Row
              key={item.label}
              item={item}
              max={scale}
              unit={unit}
              format={format}
            />
          ))}
        </ul>
      )}
      {caption ? (
        <figcaption className={styles.caption}>{caption}</figcaption>
      ) : null}
    </figure>
  );
}
