/* eslint-disable no-restricted-syntax */
/// <reference types="node" />
import { randomBytes, webcrypto } from 'node:crypto';
import { expect, jest, test } from '@jest/globals';
import { algorithms } from '../lib/algorithms.js';
import { decodeBase64 } from '../lib/base64.js';
import { decode, JwtAlgorithm, sign, verify, verifyJwks } from '../lib/jwt.js';

Object.defineProperty(globalThis, 'crypto', {
  value: { subtle: webcrypto.subtle },
});

Object.defineProperty(globalThis, 'CryptoKey', {
  value: webcrypto.CryptoKey,
});

const fetchMock = jest.fn();

Object.defineProperty(globalThis, 'fetch', {
  value: fetchMock,
});

function pemToArrayBuffer(pem: string): ArrayBuffer {
  return decodeBase64(
    pem
      .replace(/-----BEGIN.*?-----/g, '')
      .replace(/-----END.*?-----/g, '')
      .replace(/\s+/g, ''),
  );
}

function createRawSigningKey(alg: JwtAlgorithm, secret: string) {
  return crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    algorithms[alg],
    false,
    ['sign'],
  );
}

function createRawVerifyingKey(alg: JwtAlgorithm, secret: string) {
  return crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    algorithms[alg],
    false,
    ['verify'],
  );
}

function createRsVerifyingKey(alg: JwtAlgorithm) {
  return crypto.subtle.importKey(
    'spki',
    pemToArrayBuffer(`-----BEGIN PUBLIC KEY-----
      MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu1SU1LfVLPHCozMxH2Mo
      4lgOEePzNm0tRgeLezV6ffAt0gunVTLw7onLRnrq0/IzW7yWR7QkrmBL7jTKEn5u
      +qKhbwKfBstIs+bMY2Zkp18gnTxKLxoS2tFczGkPLPgizskuemMghRniWaoLcyeh
      kd3qqGElvW/VDL5AaWTg0nLVkjRo9z+40RQzuVaE8AkAFmxZzow3x+VJYKdjykkJ
      0iT9wCS0DRTXu269V264Vf/3jvredZiKRkgwlL9xNAwxXFg0x/XFw005UWVRIkdg
      cKWTjpBP2dPwVZ4WWC+9aGVd+Gyn1o0CLelf4rEjGoXbAAEgAqeGUxrcIlbjXfbc
      mwIDAQAB
      -----END PUBLIC KEY-----`),
    algorithms[alg],
    false,
    ['verify'],
  );
}

function createRsSigningKey(alg: JwtAlgorithm) {
  return crypto.subtle.importKey(
    'pkcs8',
    pemToArrayBuffer(`-----BEGIN PRIVATE KEY-----
      MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQC7VJTUt9Us8cKj
      MzEfYyjiWA4R4/M2bS1GB4t7NXp98C3SC6dVMvDuictGeurT8jNbvJZHtCSuYEvu
      NMoSfm76oqFvAp8Gy0iz5sxjZmSnXyCdPEovGhLa0VzMaQ8s+CLOyS56YyCFGeJZ
      qgtzJ6GR3eqoYSW9b9UMvkBpZODSctWSNGj3P7jRFDO5VoTwCQAWbFnOjDfH5Ulg
      p2PKSQnSJP3AJLQNFNe7br1XbrhV//eO+t51mIpGSDCUv3E0DDFcWDTH9cXDTTlR
      ZVEiR2BwpZOOkE/Z0/BVnhZYL71oZV34bKfWjQIt6V/isSMahdsAASACp4ZTGtwi
      VuNd9tybAgMBAAECggEBAKTmjaS6tkK8BlPXClTQ2vpz/N6uxDeS35mXpqasqskV
      laAidgg/sWqpjXDbXr93otIMLlWsM+X0CqMDgSXKejLS2jx4GDjI1ZTXg++0AMJ8
      sJ74pWzVDOfmCEQ/7wXs3+cbnXhKriO8Z036q92Qc1+N87SI38nkGa0ABH9CN83H
      mQqt4fB7UdHzuIRe/me2PGhIq5ZBzj6h3BpoPGzEP+x3l9YmK8t/1cN0pqI+dQwY
      dgfGjackLu/2qH80MCF7IyQaseZUOJyKrCLtSD/Iixv/hzDEUPfOCjFDgTpzf3cw
      ta8+oE4wHCo1iI1/4TlPkwmXx4qSXtmw4aQPz7IDQvECgYEA8KNThCO2gsC2I9PQ
      DM/8Cw0O983WCDY+oi+7JPiNAJwv5DYBqEZB1QYdj06YD16XlC/HAZMsMku1na2T
      N0driwenQQWzoev3g2S7gRDoS/FCJSI3jJ+kjgtaA7Qmzlgk1TxODN+G1H91HW7t
      0l7VnL27IWyYo2qRRK3jzxqUiPUCgYEAx0oQs2reBQGMVZnApD1jeq7n4MvNLcPv
      t8b/eU9iUv6Y4Mj0Suo/AU8lYZXm8ubbqAlwz2VSVunD2tOplHyMUrtCtObAfVDU
      AhCndKaA9gApgfb3xw1IKbuQ1u4IF1FJl3VtumfQn//LiH1B3rXhcdyo3/vIttEk
      48RakUKClU8CgYEAzV7W3COOlDDcQd935DdtKBFRAPRPAlspQUnzMi5eSHMD/ISL
      DY5IiQHbIH83D4bvXq0X7qQoSBSNP7Dvv3HYuqMhf0DaegrlBuJllFVVq9qPVRnK
      xt1Il2HgxOBvbhOT+9in1BzA+YJ99UzC85O0Qz06A+CmtHEy4aZ2kj5hHjECgYEA
      mNS4+A8Fkss8Js1RieK2LniBxMgmYml3pfVLKGnzmng7H2+cwPLhPIzIuwytXywh
      2bzbsYEfYx3EoEVgMEpPhoarQnYPukrJO4gwE2o5Te6T5mJSZGlQJQj9q4ZB2Dfz
      et6INsK0oG8XVGXSpQvQh3RUYekCZQkBBFcpqWpbIEsCgYAnM3DQf3FJoSnXaMhr
      VBIovic5l0xFkEHskAjFTevO86Fsz1C2aSeRKSqGFoOQ0tmJzBEs1R6KqnHInicD
      TQrKhArgLXX4v3CddjfTRJkFWDbE/CkvKZNOrcf1nhaGCPspRJj2KUkj1Fhl9Cnc
      dn/RsYEONbwQSjIfMPkvxF+8HQ==
      -----END PRIVATE KEY-----`),
    algorithms[alg],
    false,
    ['sign'],
  );
}

function createRsJwksSigningKey(alg: JwtAlgorithm) {
  return crypto.subtle.importKey(
    'pkcs8',
    pemToArrayBuffer(`-----BEGIN PRIVATE KEY-----
      MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQC7VJTUt9Us8cKj
      MzEfYyjiWA4R4/M2bS1GB4t7NXp98C3SC6dVMvDuictGeurT8jNbvJZHtCSuYEvu
      NMoSfm76oqFvAp8Gy0iz5sxjZmSnXyCdPEovGhLa0VzMaQ8s+CLOyS56YyCFGeJZ
      qgtzJ6GR3eqoYSW9b9UMvkBpZODSctWSNGj3P7jRFDO5VoTwCQAWbFnOjDfH5Ulg
      p2PKSQnSJP3AJLQNFNe7br1XbrhV//eO+t51mIpGSDCUv3E0DDFcWDTH9cXDTTlR
      ZVEiR2BwpZOOkE/Z0/BVnhZYL71oZV34bKfWjQIt6V/isSMahdsAASACp4ZTGtwi
      VuNd9tybAgMBAAECggEBAKTmjaS6tkK8BlPXClTQ2vpz/N6uxDeS35mXpqasqskV
      laAidgg/sWqpjXDbXr93otIMLlWsM+X0CqMDgSXKejLS2jx4GDjI1ZTXg++0AMJ8
      sJ74pWzVDOfmCEQ/7wXs3+cbnXhKriO8Z036q92Qc1+N87SI38nkGa0ABH9CN83H
      mQqt4fB7UdHzuIRe/me2PGhIq5ZBzj6h3BpoPGzEP+x3l9YmK8t/1cN0pqI+dQwY
      dgfGjackLu/2qH80MCF7IyQaseZUOJyKrCLtSD/Iixv/hzDEUPfOCjFDgTpzf3cw
      ta8+oE4wHCo1iI1/4TlPkwmXx4qSXtmw4aQPz7IDQvECgYEA8KNThCO2gsC2I9PQ
      DM/8Cw0O983WCDY+oi+7JPiNAJwv5DYBqEZB1QYdj06YD16XlC/HAZMsMku1na2T
      N0driwenQQWzoev3g2S7gRDoS/FCJSI3jJ+kjgtaA7Qmzlgk1TxODN+G1H91HW7t
      0l7VnL27IWyYo2qRRK3jzxqUiPUCgYEAx0oQs2reBQGMVZnApD1jeq7n4MvNLcPv
      t8b/eU9iUv6Y4Mj0Suo/AU8lYZXm8ubbqAlwz2VSVunD2tOplHyMUrtCtObAfVDU
      AhCndKaA9gApgfb3xw1IKbuQ1u4IF1FJl3VtumfQn//LiH1B3rXhcdyo3/vIttEk
      48RakUKClU8CgYEAzV7W3COOlDDcQd935DdtKBFRAPRPAlspQUnzMi5eSHMD/ISL
      DY5IiQHbIH83D4bvXq0X7qQoSBSNP7Dvv3HYuqMhf0DaegrlBuJllFVVq9qPVRnK
      xt1Il2HgxOBvbhOT+9in1BzA+YJ99UzC85O0Qz06A+CmtHEy4aZ2kj5hHjECgYEA
      mNS4+A8Fkss8Js1RieK2LniBxMgmYml3pfVLKGnzmng7H2+cwPLhPIzIuwytXywh
      2bzbsYEfYx3EoEVgMEpPhoarQnYPukrJO4gwE2o5Te6T5mJSZGlQJQj9q4ZB2Dfz
      et6INsK0oG8XVGXSpQvQh3RUYekCZQkBBFcpqWpbIEsCgYAnM3DQf3FJoSnXaMhr
      VBIovic5l0xFkEHskAjFTevO86Fsz1C2aSeRKSqGFoOQ0tmJzBEs1R6KqnHInicD
      TQrKhArgLXX4v3CddjfTRJkFWDbE/CkvKZNOrcf1nhaGCPspRJj2KUkj1Fhl9Cnc
      dn/RsYEONbwQSjIfMPkvxF+8HQ==
      -----END PRIVATE KEY-----`),
    algorithms[alg],
    true,
    ['sign'],
  );
}

function createRsJwksVerifyingKey(alg: JwtAlgorithm) {
  return crypto.subtle.importKey(
    'spki',
    pemToArrayBuffer(`-----BEGIN PUBLIC KEY-----
      MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu1SU1LfVLPHCozMxH2Mo
      4lgOEePzNm0tRgeLezV6ffAt0gunVTLw7onLRnrq0/IzW7yWR7QkrmBL7jTKEn5u
      +qKhbwKfBstIs+bMY2Zkp18gnTxKLxoS2tFczGkPLPgizskuemMghRniWaoLcyeh
      kd3qqGElvW/VDL5AaWTg0nLVkjRo9z+40RQzuVaE8AkAFmxZzow3x+VJYKdjykkJ
      0iT9wCS0DRTXu269V264Vf/3jvredZiKRkgwlL9xNAwxXFg0x/XFw005UWVRIkdg
      cKWTjpBP2dPwVZ4WWC+9aGVd+Gyn1o0CLelf4rEjGoXbAAEgAqeGUxrcIlbjXfbc
      mwIDAQAB
      -----END PUBLIC KEY-----`),
    algorithms[alg],
    true,
    ['verify'],
  );
}

function createEsVerifyingKey(alg: JwtAlgorithm, pem: string) {
  return crypto.subtle.importKey(
    'spki',
    pemToArrayBuffer(pem),
    algorithms[alg],
    false,
    ['verify'],
  );
}

function createEsSigningKey(alg: JwtAlgorithm, pem: string) {
  return crypto.subtle.importKey(
    'pkcs8',
    pemToArrayBuffer(pem),
    algorithms[alg],
    false,
    ['sign'],
  );
}

const keys: Record<JwtAlgorithm, { sign: CryptoKey; verify: CryptoKey }> = {
  HS256: {
    sign: await createRawSigningKey('HS256', 'secret'),
    verify: await createRawVerifyingKey('HS256', 'secret'),
  },
  HS384: {
    sign: await createRawSigningKey('HS384', 'secret'),
    verify: await createRawVerifyingKey('HS384', 'secret'),
  },
  HS512: {
    sign: await createRawSigningKey('HS512', 'secret'),
    verify: await createRawVerifyingKey('HS512', 'secret'),
  },
  RS256: {
    sign: await createRsSigningKey('RS256'),
    verify: await createRsVerifyingKey('RS256'),
  },
  RS384: {
    sign: await createRsSigningKey('RS384'),
    verify: await createRsVerifyingKey('RS384'),
  },
  RS512: {
    sign: await createRsSigningKey('RS512'),
    verify: await createRsVerifyingKey('RS512'),
  },
  ES256: {
    sign: await createEsSigningKey(
      'ES256',
      `-----BEGIN PRIVATE KEY-----
      MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgevZzL1gdAFr88hb2
      OF/2NxApJCzGCEDdfSp6VQO30hyhRANCAAQRWz+jn65BtOMvdyHKcvjBeBSDZH2r
      1RTwjmYSi9R/zpBnuQ4EiMnCqfMPWiZqB4QdbAd0E7oH50VpuZ1P087G
      -----END PRIVATE KEY-----`,
    ),
    verify: await createEsVerifyingKey(
      'ES256',
      `-----BEGIN PUBLIC KEY-----
      MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEEVs/o5+uQbTjL3chynL4wXgUg2R9
      q9UU8I5mEovUf86QZ7kOBIjJwqnzD1omageEHWwHdBO6B+dFabmdT9POxg==
      -----END PUBLIC KEY-----`,
    ),
  },
  ES384: {
    sign: await createEsSigningKey(
      'ES384',
      `-----BEGIN PRIVATE KEY-----
      MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDCAHpFQ62QnGCEvYh/p
      E9QmR1C9aLcDItRbslbmhen/h1tt8AyMhskeenT+rAyyPhGhZANiAAQLW5ZJePZz
      MIPAxMtZXkEWbDF0zo9f2n4+T1h/2sh/fviblc/VTyrv10GEtIi5qiOy85Pf1RRw
      8lE5IPUWpgu553SteKigiKLUPeNpbqmYZUkWGh3MLfVzLmx85ii2vMU=
      -----END PRIVATE KEY-----`,
    ),
    verify: await createEsVerifyingKey(
      'ES384',
      `-----BEGIN PUBLIC KEY-----
      MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEC1uWSXj2czCDwMTLWV5BFmwxdM6PX9p+
      Pk9Yf9rIf374m5XP1U8q79dBhLSIuaojsvOT39UUcPJROSD1FqYLued0rXiooIii
      1D3jaW6pmGVJFhodzC31cy5sfOYotrzF
      -----END PUBLIC KEY-----`,
    ),
  },
  ES512: {
    sign: await createEsSigningKey(
      'ES512',
      `-----BEGIN PRIVATE KEY-----
      MIHuAgEAMBAGByqGSM49AgEGBSuBBAAjBIHWMIHTAgEBBEIBiyAa7aRHFDCh2qga
      9sTUGINE5jHAFnmM8xWeT/uni5I4tNqhV5Xx0pDrmCV9mbroFtfEa0XVfKuMAxxf
      Z6LM/yKhgYkDgYYABAGBzgdnP798FsLuWYTDDQA7c0r3BVk8NnRUSexpQUsRilPN
      v3SchO0lRw9Ru86x1khnVDx+duq4BiDFcvlSAcyjLACJvjvoyTLJiA+TQFdmrear
      jMiZNE25pT2yWP1NUndJxPcvVtfBW48kPOmvkY4WlqP5bAwCXwbsKrCgk6xbsp12
      ew==
      -----END PRIVATE KEY-----`,
    ),
    verify: await createEsVerifyingKey(
      'ES512',
      `-----BEGIN PUBLIC KEY-----
      MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBgc4HZz+/fBbC7lmEww0AO3NK9wVZ
      PDZ0VEnsaUFLEYpTzb90nITtJUcPUbvOsdZIZ1Q8fnbquAYgxXL5UgHMoywAib47
      6MkyyYgPk0BXZq3mq4zImTRNuaU9slj9TVJ3ScT3L1bXwVuPJDzpr5GOFpaj+WwM
      Al8G7CqwoJOsW7Kddns=
      -----END PUBLIC KEY-----`,
    ),
  },
};

test.each(Object.entries(keys))('Sign + Verify: %s', async (algorithm, key) => {
  const testPayload = {
    sub: '123aaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
    name: 'Test User',
    jti: randomBytes(6).toString('hex'),
  };

  const token = await sign(testPayload, key.sign, {
    algorithm,
  } as { algorithm: JwtAlgorithm });

  expect(token).toMatch(/^[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+$/);

  const { header, payload } = decode(token);
  expect({ header, payload }).toMatchSnapshot({
    payload: {
      iat: expect.any(Number),
      jti: expect.any(String),
    },
  });

  const verified = await verify(token, key.verify);
  expect(verified).toStrictEqual({ header, payload });
});

const externalTokens: Record<JwtAlgorithm, string> = {
  ES256:
    'eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.Ri9u3ZJpyoHf1_i3KpVE5gMggyU3VMYPeEVktAsG1kGLOxFNJBXydQls3WFBaXXH2-sN74IMe-nDcM7NoJ6GMQ',
  ES384:
    'eyJhbGciOiJFUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.6nmlvcCpsfENb6ssgX3rJ2XSjpFSXD1RPS1CK0iDZFdi6I6Gnmpi456RSW6-0XSSgq2E2XBcWCSYE6TeI63jOGZJTQ6-65g4sndbzBPqYPWbLny00NQ4MQgQXVu6tRzg',
  ES512:
    'eyJhbGciOiJFUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.AbRwaCPJM2X3XjE2kInClHVGJNIcpL5C4a1ZrgwEM05RTryyNbazWRFbXAEDtHm8crvXpqw3a8JQwYDwvMyoOr4jAJ4RbhJitLgCGEzhKjvNy4xGrg3dV8gGEShFowgDfVz0KqHOX_Bc_DbyL-gtZPdfGTwT2upLkJE-lj47RStPDh0b',
  HS256:
    'eyJ0eXBlIjoiSldUIiwiYWxnIjoiSFMyNTYifQ.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNjYwMzEzNzAyfQ.O24DwvLGrbbXvB7TlPG8dgQhBHD5nL22UD33eOGTK5Q',
  HS384:
    'eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.hO2sthNQUSfvI9ylUdMKDxcrm8jB3KL6Rtkd3FOskL-jVqYh2CK1es8FKCQO8_tW',
  HS512:
    'eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.wUVS6tazE2N98_J4SH_djkEe1igXPu0qILAvVXCiO6O20gdf5vZ2sYFWX3c-Hy6L4TD47b3DSAAO9XjSqpJfag',
  RS256:
    'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.Eci61G6w4zh_u9oOCk_v1M_sKcgk0svOmW4ZsL-rt4ojGUH2QY110bQTYNwbEVlowW7phCg7vluX_MCKVwJkxJT6tMk2Ij3Plad96Jf2G2mMsKbxkC-prvjvQkBFYWrYnKWClPBRCyIcG0dVfBvqZ8Mro3t5bX59IKwQ3WZ7AtGBYz5BSiBlrKkp6J1UmP_bFV3eEzIHEFgzRa3pbr4ol4TK6SnAoF88rLr2NhEz9vpdHglUMlOBQiqcZwqrI-Z4XDyDzvnrpujIToiepq9bCimPgVkP54VoZzy-mMSGbthYpLqsL_4MQXaI1Uf_wKFAUuAtzVn4-ebgsKOpvKNzVA',
  RS384:
    'eyJhbGciOiJSUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.oPvWzaCp8xUpt5mHhPSn0qLsZfCFj0NVmb4mz4dFQPCCMj-F5zVn9e3zZoj0lIXWM8rxB69QHC3Er47mtDt3BKgysTL3BvvV89kD6UjLoUcAI3lwj0mi7acLoE27i1_TnIBqWNRPAsdvTDawNE0_4lvI5bxEWQCqisJwxCoMDIeJsmDzfyApgU_SAFSVULxXwU2VewaxdQB-41OZdWwUEAxh81iB6DFWrqd2CaJkUYoWjgYpeWsyeC2m_-ECGrHGEz1nKTm9c7BaPxurz7fHD7RJd9Wpx-mKDVsfspO9quWb_OLeGGbxTtAomMvjQjut56kx2fqTleDnNDh_0GE88w',
  RS512:
    'eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.kEZmDAnHHU_0bcGXMd5LA7vF87yQgXNaioPHP4lU4O3JJYuZ54fJdv3HT58xk-MFEDuWro_5fvNIp2VM-PlkZvYWrhQkJ-c-seoSa3ANq_PciC3bGfzYHEdjAE71GrAMI4FlcAGsq3ChkOnCTFqjWDmVwaRYCgMsFQ-U5cjvFhndFMizrkRljTF4v5oFdWytV_J-UafPtNdQXcGND1M74DqObnTHhZHg8aDfNzZcvnIeKcDVGUlUEL5ia1kPMrVhCtOAOJmEU8ivCdWWzt-jMQBf7cZeoCzDKHG72ysTTCfRoBVc1_SrQTHcHDiiBeW9nCazMLkltyP5NeawR_RNlg',
};

test.each(Object.entries(externalTokens))(
  'Verify external tokens: %s',
  async (algorithm, token) => {
    const key = keys[algorithm as JwtAlgorithm];

    const verified = await verify(token, key.verify);
    expect(verified).toBeTruthy();

    const decoded = decode(token);
    expect(decoded).toMatchSnapshot();
  },
);

test('Verify JWKS external tokens: %s', async () => {
  const algorithm = 'RS256';
  const kid = randomBytes(12).toString('base64url');
  const jwksSigningKey = await createRsJwksSigningKey(algorithm);
  const jwksVerifyingKey = await createRsJwksVerifyingKey(algorithm);

  const jwks: { keys: (JsonWebKey & { kid: string })[] } = {
    keys: [
      {
        kid,
        // use: 'sig',
        ...(await crypto.subtle.exportKey('jwk', jwksVerifyingKey)),
      },
    ],
  };

  fetchMock.mockImplementationOnce(() =>
    Promise.resolve({
      json: async () => jwks,
    }),
  );

  // console.log(jwks.keys[0]);

  const token = await sign(
    {
      jti: randomBytes(12).toString('base64url'),
    },
    jwksSigningKey,
    {
      algorithm,
      kid,
    },
  );

  const verified = await verifyJwks(token, new URL('https://localhost/jwks'));
  expect(verified).toBeTruthy();

  const { header, payload } = verified;
  expect({ header, payload }).toMatchSnapshot({
    header: {
      kid: expect.any(String),
    },
    payload: {
      iat: expect.any(Number),
      jti: expect.any(String),
    },
  });
});
