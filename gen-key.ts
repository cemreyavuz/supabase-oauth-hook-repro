/**
 * Writes `supabase/signing_keys.json` with one ES256 (P-256) private JWK, the
 * shape that `[auth] signing_keys_path` in `config.toml` expects.
 */
import { generateKeyPairSync, randomUUID } from 'node:crypto';

const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
const jwk = {
  ...privateKey.export({ format: 'jwk' }),
  kid: randomUUID(),
  use: 'sig',
  key_ops: ['sign', 'verify'],
  alg: 'ES256',
  ext: true
};

await Bun.write('supabase/signing_keys.json', JSON.stringify([jwk]));
console.log(`Wrote supabase/signing_keys.json (kid ${jwk.kid})`);
