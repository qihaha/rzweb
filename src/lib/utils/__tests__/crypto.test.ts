import { describe, expect, it } from 'vitest';
import { digestSha256Hex, randomId, sha256HexFallback } from '../crypto';

const encoder = new TextEncoder();

// NIST known-answer vectors for SHA-256.
const VECTORS: Array<[string, string]> = [
  ['', 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'],
  ['abc', 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'],
  [
    'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq',
    '248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1',
  ],
];

describe('sha256HexFallback', () => {
  for (const [input, expected] of VECTORS) {
    it(`hashes ${JSON.stringify(input.slice(0, 12))} correctly`, () => {
      expect(sha256HexFallback(encoder.encode(input))).toBe(expected);
    });
  }

  it('handles inputs spanning multiple blocks', () => {
    const data = new Uint8Array(1000).map((_, i) => i % 256);
    expect(sha256HexFallback(data)).toMatch(/^[0-9a-f]{64}$/);
    expect(sha256HexFallback(data)).toBe(sha256HexFallback(data.slice()));
  });
});

describe('digestSha256Hex', () => {
  for (const [input, expected] of VECTORS) {
    it(`matches vector ${JSON.stringify(input.slice(0, 12))}`, async () => {
      await expect(digestSha256Hex(encoder.encode(input))).resolves.toBe(expected);
    });
  }
});

describe('randomId', () => {
  it('returns a v4-shaped UUID', () => {
    const id = randomId();
    expect(id).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
    expect(randomId()).not.toBe(id);
  });
});
