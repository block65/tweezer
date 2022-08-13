import { algorithms } from './algorithms.js';
import {
  base64UrlToObject,
  decodeBase64Url,
  encodeBase64Url,
  objectToBase64Url,
} from './base64.js';
import {
  assertArray,
  assertObject,
  assertString,
  assertStringKeyInObject,
} from './utils.js';

export type JwtAlgorithm =
  | 'ES256'
  | 'ES384'
  | 'ES512'
  | 'HS256'
  | 'HS384'
  | 'HS512'
  | 'RS256'
  | 'RS384'
  | 'RS512';

export interface JwtHeader {
  typ: 'JWT';
  alg: JwtAlgorithm;
  kid?: string;
  [key: string]: unknown;
}

export interface JwtPayload {
  /** Issuer */
  iss?: string;

  /** Subject */
  sub?: string;

  /** Audience */
  aud?: string;

  /** Expiration Time */
  exp?: number;

  /** Not Before */
  nbf?: number;

  /** Issued At */
  iat?: number;

  /** JWT ID */
  jti: string;

  [key: string]: unknown;
}

export function decode(token: string) {
  const tokenParts = token.split('.') as [string, string, string];

  if (tokenParts.length !== 3) {
    throw new Error('token must consist of 3 parts');
  }

  const [headerEncoded, payloadEncoded, signatureEncoded] = tokenParts;

  return {
    // headerStr,
    header: base64UrlToObject<JwtHeader>(headerEncoded),
    // payloadStr,
    payload: base64UrlToObject<JwtPayload>(payloadEncoded),
    // signatureStr,
    signature: decodeBase64Url(signatureEncoded),
    signedData: new TextEncoder().encode(`${headerEncoded}.${payloadEncoded}`),
  };
}

export async function sign(
  payload: JwtPayload,
  key: CryptoKey,
  options: {
    algorithm: JwtAlgorithm;
    kid?: string;
  },
): Promise<string> {
  if (payload === null || typeof payload !== 'object') {
    throw new Error('payload must be an object');
  }

  if (!(key instanceof CryptoKey)) {
    throw new Error('key must be a CryptoKey');
  }

  if (typeof options.algorithm !== 'string') {
    throw new Error('options.algorithm must be a string');
  }

  const headerStr = objectToBase64Url<JwtHeader>({
    typ: 'JWT',
    alg: options.algorithm,
    ...(options.kid && { kid: options.kid }),
  });

  const payloadStr = objectToBase64Url<JwtPayload>({
    iat: Math.floor(Date.now() / 1000),
    ...payload,
  });

  const dataStr = `${headerStr}.${payloadStr}`;

  const signature = await crypto.subtle.sign(
    algorithms[options.algorithm],
    key,
    new TextEncoder().encode(dataStr),
  );

  return `${dataStr}.${encodeBase64Url(signature)}`;
}

export async function verify(
  token: string,
  key: CryptoKey,
): Promise<{ header: JwtHeader; payload: JwtPayload }> {
  if (typeof token !== 'string') {
    throw new Error('token argument must be a string');
  }

  if (!(key instanceof CryptoKey)) {
    throw new Error('key argument must be a CryptoKey');
  }

  const { header, payload, signature, signedData } = decode(token);

  if (payload.nbf && payload.nbf > Math.floor(Date.now() / 1000)) {
    throw new Error('NOT_YET_VALID');
  }

  if (payload.exp && payload.exp <= Math.floor(Date.now() / 1000)) {
    throw new Error('EXPIRED');
  }

  const verified = await crypto.subtle.verify(
    algorithms[header.alg],
    key,
    signature,
    signedData,
  );

  if (!verified) {
    throw new Error('Token did not verify');
  }
  return { header, payload };
}

export async function verifyJwks(
  token: string,
  jwksUri: URL,
): Promise<{ header: JwtHeader; payload: JwtPayload }> {
  if (typeof token !== 'string') {
    throw new Error('token argument must be a string');
  }

  const { header } = decode(token);

  const jwks = await fetch(jwksUri).then((res) => res.json());
  // .catch((err) => {
  //   throw new Error(`${err.message} for ${jwksUri.toString()}`);
  // });

  assertObject(jwks);
  assertArray(jwks['keys']);

  const key = header.kid
    ? jwks['keys'].find((k) => {
        assertObject(k);
        return k['kid'] === header.kid;
      })
    : jwks['keys'].at(0);

  assertObject(key);
  assertStringKeyInObject(key, 'alg');
  assertString<JwtAlgorithm>(key.alg);

  // assertKeyInObject(key, 'e');
  // assertKeyInObject(key, 'kty');
  // assertKeyInObject(key, 'n');
  // assertKeyInObject(key, 'use');

  const algorithm = algorithms[key.alg];

  const keyData = await crypto.subtle.importKey('jwk', key, algorithm, false, [
    'verify',
  ]);

  return verify(token, keyData);
}
