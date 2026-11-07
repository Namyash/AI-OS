import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

const tokensCss = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), '..', 'src', 'styles', 'tokens.css'),
  'utf8',
);

type Palette = Record<string, string>;

function declarationsIn(block: string): Palette {
  const result: Palette = {};
  for (const match of block.matchAll(/--([\w-]+):\s*([^;]+);/g)) {
    const [, name, value] = match;
    if (name !== undefined && value !== undefined) {
      result[name] = value.trim();
    }
  }
  return result;
}

function rootBlock(css: string): string {
  const block = /:root\s*\{([^}]*)\}/.exec(css)?.[1];
  if (block === undefined) {
    throw new Error('tokens.css has no :root block where one was expected');
  }
  return block;
}

const light = declarationsIn(rootBlock(tokensCss));
const darkMedia = tokensCss.slice(tokensCss.indexOf('@media (prefers-color-scheme: dark)'));
const dark: Palette = { ...light, ...declarationsIn(rootBlock(darkMedia)) };

/** Follows `var(--other)` references and returns a #rrggbb value. */
function colour(palette: Palette, name: string): string {
  const value = palette[name];
  if (value === undefined) {
    throw new Error(`token --${name} is not defined`);
  }
  const reference = /^var\(--([\w-]+)\)$/.exec(value);
  if (reference?.[1] !== undefined) {
    return colour(palette, reference[1]);
  }
  if (!/^#[0-9a-f]{6}$/i.test(value)) {
    throw new Error(`token --${name} is not a #rrggbb colour: ${value}`);
  }
  return value;
}

function channel(hex: string, offset: number): number {
  const value = Number.parseInt(hex.slice(offset, offset + 2), 16) / 255;
  return value <= 0.03928 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4;
}

/** WCAG 2.x relative luminance and contrast ratio. */
function contrast(foreground: string, background: string): number {
  const luminance = (hex: string) => 0.2126 * channel(hex, 1) + 0.7152 * channel(hex, 3) + 0.0722 * channel(hex, 5);
  const [lighter, darker] = [luminance(foreground), luminance(background)].sort((a, b) => b - a);
  return ((lighter ?? 0) + 0.05) / ((darker ?? 0) + 0.05);
}

/** WCAG 1.4.3: 4.5:1 for text. WCAG 1.4.11: 3:1 for the outlines and marks that identify controls and states. */
const TEXT = 4.5;
const GRAPHIC = 3;

const requirements: Array<{ foreground: string; backgrounds: string[]; minimum: number; use: string }> = [
  { foreground: 'ink', backgrounds: ['ground', 'surface'], minimum: TEXT, use: 'body text' },
  { foreground: 'ink-muted', backgrounds: ['ground', 'surface'], minimum: TEXT, use: 'secondary text' },
  { foreground: 'ground', backgrounds: ['ink'], minimum: TEXT, use: 'selected text' },
  { foreground: 'attention', backgrounds: ['ground', 'surface'], minimum: TEXT, use: 'attention mark' },
  { foreground: 'danger', backgrounds: ['ground', 'surface'], minimum: TEXT, use: 'danger mark' },
  { foreground: 'control-border', backgrounds: ['ground', 'surface'], minimum: GRAPHIC, use: 'control outline' },
  { foreground: 'focus', backgrounds: ['ground', 'surface'], minimum: GRAPHIC, use: 'focus ring' },
];

describe('colour tokens meet WCAG AA', () => {
  for (const [theme, palette] of [
    ['light', light],
    ['dark', dark],
  ] as const) {
    describe(`${theme} theme`, () => {
      for (const { foreground, backgrounds, minimum, use } of requirements) {
        for (const background of backgrounds) {
          it(`${use}: --${foreground} on --${background} is at least ${minimum}:1`, () => {
            expect(contrast(colour(palette, foreground), colour(palette, background))).toBeGreaterThanOrEqual(minimum);
          });
        }
      }
    });
  }

  it('really defines a separate dark palette', () => {
    expect(colour(dark, 'ground')).not.toBe(colour(light, 'ground'));
    expect(colour(dark, 'ink')).not.toBe(colour(light, 'ink'));
  });

  it('computes contrast correctly (black on white is 21:1)', () => {
    expect(contrast('#000000', '#ffffff')).toBeCloseTo(21, 5);
  });
});
