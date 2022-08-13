import { Method, Params, Router } from 'tiny-request-router';
import { algorithms } from '../lib/algorithms.js';
import { decodeBase64 } from '../lib/base64.js';
import { JwtPayload, verify } from '../lib/jwt.js';
import {
  assertArray,
  assertKeyInObject,
  assertObject,
  assertTruthy,
} from '../lib/utils.js';

export interface Env {
  channels: DurableObjectNamespace;
  TWEEZER_KEY: string;
}

export type Handler = (
  req: Request,
  params: Record<string, string>,
  env: Env,
) => Promise<Response>;

function forbiddenHandler(_req: Request): Response {
  return new Response(null, {
    status: 403,
    headers: {
      // 'content-type': 'text/plain;charset="utf-8"',
    },
  });
}

export class Channel implements DurableObject {
  private readonly sessions = new Set<WritableStream>();

  private readonly env: Env;

  private router: Router<Handler>;

  private lastEventId = 0;

  constructor(_controller: unknown, env: Env) {
    this.env = env;

    this.router = new Router<Handler>();
    this.router.post('/channels/:channelId', async (req) => {
      const body = await req.text();

      const eventId = this.lastEventId + 1;

      this.lastEventId = eventId;

      // eslint-disable-next-line no-restricted-syntax
      for await (const session of this.sessions) {
        const writer = session.getWriter();

        // await writer.ready;

        await writer
          .write(new TextEncoder().encode(`id: ${eventId}\ndata: ${body}\n\n`))
          .catch((err) => {
            // eslint-disable-next-line no-console
            console.warn(err);
            this.sessions.delete(session);
          })
          .finally(() => {
            // await writer.ready;
            // console.log('xb4 writer.releaseLock');
            writer.releaseLock();
          });
      }

      return new Response(
        JSON.stringify({
          result: `broadcasted to ${this.sessions.size} streams`,
        }),
        {
          headers: {
            'content-type': 'application/json',
          },
        },
      );
    });

    this.router.get('/channels/:channelId', async (/* req, params */) => {
      const { readable, writable } = new TransformStream();

      this.sessions.add(writable);

      const headers = new Headers();
      headers.append('content-type', 'text/event-stream');
      headers.append('cache-control', 'no-cache');
      headers.append('connection', 'keep-alive');
      headers.append('access-control-allow-origin', '*');
      headers.append(
        'Access-Control-Allow-Headers',
        'Origin, X-Requested-With, Content-Type, Accept',
      );

      const writer = writable.getWriter();
      // await writer.ready;

      // WARN: we don't await here deliberately.
      // We do not block the forward progress of the function, and write()
      // will not resolve until the stream starts being read by the client
      writer
        .write(new TextEncoder().encode(':ok\n'))
        .then(() => writer.releaseLock())
        // eslint-disable-next-line no-console
        .catch((err) => console.warn(err));

      return new Response(readable, {
        status: 200,
        statusText: 'ok',
        headers,
      });
    });
  }

  public async fetch(req: Request) {
    const { pathname } = new URL(req.url);
    const match = this.router.match(req.method as Method, pathname);

    if (match) {
      return match.handler(req, match.params, this.env);
    }
    return forbiddenHandler(req);
  }
}

const router = new Router<Handler>();

function parseJwt(
  auth: JwtPayload,
  channelId: string,
  action: 'subscribe' | 'post',
) {
  assertKeyInObject(auth, 'cap');
  assertObject(auth.cap);
  assertKeyInObject(auth.cap, channelId);

  const actions = auth.cap[channelId];

  assertArray(actions);
  assertTruthy(actions.includes(action));
}

router.post('/channels/:channelId', async (req, params, env) => {
  const { channelId } = params;

  if (!channelId) {
    return forbiddenHandler(req);
  }

  const id = env.channels.idFromName(channelId);
  const instance = env.channels.get(id);
  return instance.fetch(req);
});

router.get('/channels/:channelId', async (req, params, env) => {
  const { channelId } = params;

  if (!channelId) {
    return forbiddenHandler(req);
  }

  const id = env.channels.idFromName(channelId);
  const instance = env.channels.get(id);
  return instance.fetch(req);
});

router.get('/event-stream', async (req: Request, _params: Params, env: Env) => {
  const reqUrl = new URL(req.url);

  const { searchParams } = reqUrl;
  const [channelId] = searchParams.getAll('channels');

  if (!channelId) {
    return forbiddenHandler(req);
  }

  const accessToken = searchParams.get('accessToken');
  if (!accessToken) {
    return forbiddenHandler(req);
  }

  const key = await crypto.subtle.importKey(
    'raw',
    decodeBase64(env.TWEEZER_KEY),
    algorithms.HS256,
    false,
    ['sign', 'verify'],
  );

  const verified = await verify(accessToken, key).catch((err) => {
    console.warn(err);
  });

  if (!verified) {
    return forbiddenHandler(req);
  }

  parseJwt(verified.payload, channelId, 'subscribe');

  const id = env.channels.idFromName(channelId);
  const instance = env.channels.get(id);

  // Rewrite URL
  return instance.fetch(
    Object.assign<URL, Partial<URL>>(new URL(reqUrl), {
      pathname: '/channels/:channelId',
    }).toString(),
    req,
  );
});

export default {
  async fetch(req: Request, env: Env) {
    const { pathname } = new URL(req.url);
    const match = router.match(req.method as Method, pathname);

    if (match) {
      return match.handler(req, match.params, env);
    }
    return forbiddenHandler(req);
  },
};
