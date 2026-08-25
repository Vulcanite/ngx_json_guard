import React from 'react';
import styles from './BenchCharts.module.css';

/*
 * Published 2026-08-24 numbers from BENCHMARK.md (commit 08851ee).
 * Do not "round for the chart" beyond what the source tables already print.
 */
export const PARSE_TIME = [
  { x: 0.1, y: 0.38, label: '100 KiB' },
  { x: 1, y: 3.7, label: '1 MiB' },
  { x: 10, y: 37.8, label: '10 MiB' },
  { x: 20, y: 75.7, label: '20 MiB' },
];

export const PARSE_THROUGHPUT = [
  { x: 0.1, y: 260, label: '100 KiB' },
  { x: 1, y: 271, label: '1 MiB' },
  { x: 10, y: 265, label: '10 MiB' },
  { x: 20, y: 264, label: '20 MiB' },
];

export const GUARD_INSPECT_MS = [
  { x: 0.0001, y: 0.01, label: '~100 B' },
  { x: 1, y: 4.1, label: '1 MiB' },
  { x: 20, y: 96.3, label: '20 MiB' },
];

export const OUTCOME_LATENCY = [
  { label: 'CRS scan\n(clean 20 MiB)', value: 2920, tone: 'crs' },
  { label: 'CRS blocks\ntail SQLi', value: 2031, tone: 'block' },
  { label: 'Guard 400\nmalformed tail', value: 313, tone: 'guard' },
  { label: 'Guard 413\nover limit', value: 241, tone: 'guard' },
];

export const ENGINE_CLASSES = [
  { label: 'Baseline', value: 0, tone: 'mute' },
  { label: 'JSON Guard', value: 11, tone: 'guard' },
  { label: 'ModSecurity', value: 7, tone: 'crs' },
  { label: 'Coraza', value: 6, tone: 'other' },
];

/* Processor-only profiles: JSON structure, no CRS. Mixed 1–100 MiB corpus. */
export const PROCESSOR_P50 = [
  { label: 'JSON Guard', value: 414, tone: 'guard' },
  { label: 'ModSecurity\nJSON only', value: 593, tone: 'crs' },
  { label: 'Coraza\nJSON only', value: 822, tone: 'other' },
];

export const PROCESSOR_P95 = [
  { label: 'JSON Guard', value: 2579, tone: 'guard' },
  { label: 'ModSecurity\nJSON only', value: 6526, tone: 'crs' },
  { label: 'Coraza\nJSON only', value: 7894, tone: 'other' },
];

export const PROCESSOR_MIB = [
  { label: 'JSON Guard', value: 167.2, tone: 'guard' },
  { label: 'ModSecurity\nJSON only', value: 74.8, tone: 'crs' },
  { label: 'Coraza\nJSON only', value: 55.7, tone: 'other' },
];

export const PROCESSOR_CAPTION =
  'Processor-only profiles (no CRS). Client-observed HTTP latency on the mixed 1–100 MiB corpus, 4 workers. Upload, proxy, and upstream are included for all three — this is not a parser-only timer. Only JSON Guard exposes $json_guard_inspection_us; ModSecurity and Coraza numbers are not fabricated parser times. Guard’s median is helped by early 400/413 on malformed/over-limit bodies in this corpus. Coraza runs on Caddy; the other two run on NGINX.';

export const PROCESSOR_CAPTION_SHORT =
  'JSON structural validation only — no CRS. HTTP p50 from BENCHMARK.md (2026-08-24), mixed 1–100 MiB corpus.';

const VB_W = 720;
const VB_H = 320;
const PAD = { top: 36, right: 28, bottom: 56, left: 58 };

function plotBox() {
  return {
    x: PAD.left,
    y: PAD.top,
    w: VB_W - PAD.left - PAD.right,
    h: VB_H - PAD.top - PAD.bottom,
  };
}

function sx(x, xMax, box, xScale, xMin) {
  if (xScale === 'log') {
    const lo = Math.log10(xMin);
    const hi = Math.log10(xMax);
    return box.x + ((Math.log10(x) - lo) / (hi - lo)) * box.w;
  }
  return box.x + (x / xMax) * box.w;
}

function sy(y, yMax, box) {
  return box.y + box.h - (y / yMax) * box.h;
}

function niceTicks(max) {
  if (max <= 0) {
    return [0];
  }
  const raw = max / 4;
  const mag = Math.pow(10, Math.floor(Math.log10(raw)));
  const r = raw / mag;
  const step = (r <= 1 ? 1 : r <= 2 ? 2 : r <= 5 ? 5 : 10) * mag;
  const out = [];
  for (let t = 0; t < max - step / 4; t += step) {
    out.push(t);
  }
  out.push(max);
  return out;
}

function splitLabel(label) {
  return String(label).split('\n');
}

export function LineChart({
  title,
  yLabel,
  xLabel,
  points,
  xMax,
  yMax,
  yFormat,
  xScale = 'linear',
  xMin = 0.1,
}) {
  const box = plotBox();
  const fmt = yFormat || ((v) => String(v));
  const path = points
    .map((p, i) => {
      const x = sx(p.x, xMax, box, xScale, xMin);
      const y = sy(p.y, yMax, box);
      return `${i === 0 ? 'M' : 'L'}${x.toFixed(1)} ${y.toFixed(1)}`;
    })
    .join(' ');

  return (
    <figure className={styles.wrap}>
      <svg
        className={styles.chart}
        viewBox={`0 0 ${VB_W} ${VB_H}`}
        role="img"
        aria-label={title}>
        <title>{title}</title>
        <text className={styles.title} x={VB_W / 2} y="18" textAnchor="middle">
          {title}
        </text>
        {niceTicks(yMax).map((t) => {
          const y = sy(t, yMax, box);
          return (
            <g key={`y-${t}`}>
              <line
                className={styles.grid}
                x1={box.x}
                x2={box.x + box.w}
                y1={y}
                y2={y}
              />
              <text
                className={styles.tick}
                x={box.x - 8}
                y={y + 4}
                textAnchor="end">
                {fmt(t)}
              </text>
            </g>
          );
        })}
        <rect
          className={styles.frame}
          x={box.x}
          y={box.y}
          width={box.w}
          height={box.h}
        />
        <path className={styles.line} d={path} />
        {points.map((p) => {
          const x = sx(p.x, xMax, box, xScale, xMin);
          const y = sy(p.y, yMax, box);
          return (
            <g key={p.label}>
              <circle className={styles.dot} cx={x} cy={y} r="5" />
              <text
                className={styles.pointLabel}
                x={x}
                y={y - 12}
                textAnchor="middle">
                {fmt(p.y)}
              </text>
              <text
                className={styles.tick}
                x={x}
                y={box.y + box.h + 18}
                textAnchor="middle">
                {p.label}
              </text>
            </g>
          );
        })}
        <text
          className={styles.axisTitle}
          transform={`translate(16 ${box.y + box.h / 2}) rotate(-90)`}
          textAnchor="middle">
          {yLabel}
        </text>
        <text
          className={styles.axisTitle}
          x={box.x + box.w / 2}
          y={VB_H - 10}
          textAnchor="middle">
          {xLabel}
        </text>
      </svg>
      <figcaption className={styles.caption}>
        Same published values as <code>BENCHMARK.md</code> (2026-08-24).
        {xScale === 'log'
          ? ' X axis is logarithmic in body size.'
          : ' X positions are proportional to body size, not equally spaced categories.'}
      </figcaption>
    </figure>
  );
}

export function BarChart({ title, yLabel, items, yMax, yFormat, caption }) {
  const box = plotBox();
  const fmt = yFormat || ((v) => String(v));
  const n = items.length;
  const gap = box.w / n;
  const barW = gap * 0.55;

  return (
    <figure className={styles.wrap}>
      <svg
        className={styles.chart}
        viewBox={`0 0 ${VB_W} ${VB_H}`}
        role="img"
        aria-label={title}>
        <title>{title}</title>
        <text className={styles.title} x={VB_W / 2} y="18" textAnchor="middle">
          {title}
        </text>
        {niceTicks(yMax).map((t) => {
          const y = sy(t, yMax, box);
          return (
            <g key={`y-${t}`}>
              <line
                className={styles.grid}
                x1={box.x}
                x2={box.x + box.w}
                y1={y}
                y2={y}
              />
              <text
                className={styles.tick}
                x={box.x - 8}
                y={y + 4}
                textAnchor="end">
                {fmt(t)}
              </text>
            </g>
          );
        })}
        <rect
          className={styles.frame}
          x={box.x}
          y={box.y}
          width={box.w}
          height={box.h}
        />
        {items.map((item, i) => {
          const h = (item.value / yMax) * box.h;
          const x = box.x + gap * i + (gap - barW) / 2;
          const y = box.y + box.h - h;
          const lines = splitLabel(item.label);
          return (
            <g key={item.label}>
              <rect
                className={styles[`bar_${item.tone}`] || styles.bar_guard}
                x={x}
                y={y}
                width={barW}
                height={Math.max(h, item.value === 0 ? 0 : 2)}
              />
              <text
                className={styles.pointLabel}
                x={x + barW / 2}
                y={y - 8}
                textAnchor="middle">
                {fmt(item.value)}
              </text>
              {lines.map((line, li) => (
                <text
                  key={line}
                  className={styles.tick}
                  x={x + barW / 2}
                  y={box.y + box.h + 16 + li * 14}
                  textAnchor="middle">
                  {line}
                </text>
              ))}
            </g>
          );
        })}
        <text
          className={styles.axisTitle}
          transform={`translate(16 ${box.y + box.h / 2}) rotate(-90)`}
          textAnchor="middle">
          {yLabel}
        </text>
      </svg>
      <figcaption className={styles.caption}>
        {caption || (
          <>
            Same published values as <code>BENCHMARK.md</code> (2026-08-24).
          </>
        )}
      </figcaption>
    </figure>
  );
}
