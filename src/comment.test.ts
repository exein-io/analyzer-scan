import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  GitHubApiError,
  MAX_COMMENT_LENGTH,
  commentBody,
  commentMarker,
  commentWarning,
  pullRequestNumber,
  restCommentApi,
  upsertComment,
  type CommentApi,
  type IssueComment,
} from './comment.js';

/** An Octokit stand-in that keeps the comments of one pull request, and records the calls. */
function fakeApi(comments: IssueComment[] = []) {
  const calls: string[] = [];
  let nextId = 1000;
  const api: CommentApi = {
    async listComments(issue) {
      calls.push(`list ${issue}`);
      return comments;
    },
    async createComment(issue, body) {
      calls.push(`create ${issue}`);
      comments.push({ id: nextId++, body });
    },
    async updateComment(id, body) {
      calls.push(`update ${id}`);
      const c = comments.find((x) => x.id === id);
      assert.ok(c, `no comment ${id}`);
      c.body = body;
    },
  };
  return { api, calls, comments };
}

describe('commentMarker', () => {
  it('names the object in a hidden HTML comment', () => {
    assert.equal(commentMarker('gateway-firmware'), '<!-- exein-analyzer-scan:gateway-firmware -->');
  });

  it('keeps a key from closing the HTML comment', () => {
    assert.equal(commentMarker('a-->b c'), '<!-- exein-analyzer-scan:a-_b_c -->');
  });
});

describe('pullRequestNumber', () => {
  const payload = { pull_request: { number: 42 } };

  it('reads the number of a pull_request event', () => {
    assert.equal(pullRequestNumber('pull_request', payload), 42);
  });

  it('reads the number of a pull_request_target event', () => {
    assert.equal(pullRequestNumber('pull_request_target', payload), 42);
  });

  it('is undefined outside a pull request event', () => {
    assert.equal(pullRequestNumber('push', payload), undefined);
    assert.equal(pullRequestNumber(undefined, payload), undefined);
  });

  it('is undefined for a payload with no pull request', () => {
    assert.equal(pullRequestNumber('pull_request', {}), undefined);
    assert.equal(pullRequestNumber('pull_request', undefined), undefined);
  });
});

describe('commentBody', () => {
  it('puts the marker first and the footer last', () => {
    assert.equal(
      commentBody('gw', '## Gate\n', '<sub>run</sub>'),
      '<!-- exein-analyzer-scan:gw -->\n## Gate\n\n<sub>run</sub>\n',
    );
  });

  it('cuts a body too long for GitHub, keeping the marker and the footer', () => {
    const body = commentBody('gw', 'x'.repeat(MAX_COMMENT_LENGTH * 2), 'footer');
    assert.ok(body.length <= MAX_COMMENT_LENGTH);
    assert.ok(body.startsWith(commentMarker('gw')));
    assert.ok(body.endsWith('the job summary has it all)\n\nfooter\n'));
  });
});

describe('upsertComment', () => {
  it('makes the comment when the pull request has none for the object', async () => {
    const { api, calls, comments } = fakeApi([{ id: 1, body: 'LGTM' }]);
    const body = commentBody('gw', 'first');
    assert.equal(await upsertComment(api, 7, 'gw', body), 'created');
    assert.deepEqual(calls, ['list 7', 'create 7']);
    assert.equal(comments.at(-1)?.body, body);
  });

  it('updates the comment of the object on the next run', async () => {
    const { api, calls, comments } = fakeApi([
      { id: 1, body: 'LGTM' },
      { id: 2, body: commentBody('gw', 'first') },
    ]);
    const body = commentBody('gw', 'second');
    assert.equal(await upsertComment(api, 7, 'gw', body), 'updated');
    assert.deepEqual(calls, ['list 7', 'update 2']);
    assert.equal(comments.length, 2);
    assert.equal(comments[1].body, body);
  });

  it('keeps one comment per object, when a workflow gates several', async () => {
    const { api, calls } = fakeApi([{ id: 2, body: commentBody('gw', 'gateway') }]);
    assert.equal(await upsertComment(api, 7, 'sensor', commentBody('sensor', 'sensor')), 'created');
    assert.deepEqual(calls, ['list 7', 'create 7']);
  });

  it('does not take a comment that only quotes the marker', async () => {
    const { api } = fakeApi([{ id: 3, body: `See ${commentMarker('gw')}` }]);
    assert.equal(await upsertComment(api, 7, 'gw', commentBody('gw', 'x')), 'created');
  });

  it('passes on an error of the API', async () => {
    const api: CommentApi = {
      listComments: async () => {
        throw new GitHubApiError(403, 'Resource not accessible by integration');
      },
      createComment: async () => {},
      updateComment: async () => {},
    };
    await assert.rejects(upsertComment(api, 7, 'gw', 'x'), GitHubApiError);
  });
});

describe('commentWarning', () => {
  it('says which permission a refused token needs', () => {
    const w = commentWarning(new GitHubApiError(403, 'POST … answered 403'));
    assert.match(w, /^Could not comment on the pull request: POST … answered 403/);
    assert.match(w, /pull-requests: write/);
  });

  it('gives no permission hint for another error', () => {
    assert.equal(
      commentWarning(new Error('fetch failed')),
      'Could not comment on the pull request: fetch failed',
    );
  });
});

describe('restCommentApi', () => {
  interface Request {
    method: string;
    url: string;
    body?: unknown;
    auth?: string;
  }

  function fakeFetch(answer: (r: Request) => { status: number; json?: unknown }) {
    const requests: Request[] = [];
    const doFetch = (async (url: string, init: RequestInit) => {
      const headers = init.headers as Record<string, string>;
      const r: Request = {
        method: init.method ?? 'GET',
        url,
        auth: headers.Authorization,
        ...(init.body ? { body: JSON.parse(init.body as string) } : {}),
      };
      requests.push(r);
      const { status, json } = answer(r);
      return new Response(json === undefined ? null : JSON.stringify(json), { status });
    }) as typeof fetch;
    return { doFetch, requests };
  }

  const options = { apiUrl: 'https://api.github.com/', repository: 'acme/fw', token: 't0k' };

  it('reads every page of comments', async () => {
    const page = (n: number, from: number) =>
      Array.from({ length: n }, (_, i) => ({ id: from + i, body: '' }));
    const { doFetch, requests } = fakeFetch((r) => ({
      status: 200,
      json: r.url.endsWith('page=1') ? page(100, 0) : page(3, 100),
    }));
    const comments = await restCommentApi({ ...options, fetch: doFetch }).listComments(5);
    assert.equal(comments.length, 103);
    assert.deepEqual(
      requests.map((r) => r.url),
      [
        'https://api.github.com/repos/acme/fw/issues/5/comments?per_page=100&page=1',
        'https://api.github.com/repos/acme/fw/issues/5/comments?per_page=100&page=2',
      ],
    );
    assert.equal(requests[0].auth, 'Bearer t0k');
  });

  it('makes and updates comments', async () => {
    const { doFetch, requests } = fakeFetch(() => ({ status: 201, json: {} }));
    const api = restCommentApi({ ...options, fetch: doFetch });
    await api.createComment(5, 'hello');
    await api.updateComment(99, 'again');
    assert.deepEqual(
      requests.map(({ method, url, body }) => ({ method, url, body })),
      [
        {
          method: 'POST',
          url: 'https://api.github.com/repos/acme/fw/issues/5/comments',
          body: { body: 'hello' },
        },
        {
          method: 'PATCH',
          url: 'https://api.github.com/repos/acme/fw/issues/comments/99',
          body: { body: 'again' },
        },
      ],
    );
  });

  it('throws the status of a refusal', async () => {
    const { doFetch } = fakeFetch(() => ({ status: 403, json: { message: 'Resource not accessible' } }));
    await assert.rejects(
      restCommentApi({ ...options, fetch: doFetch }).createComment(5, 'x'),
      (err: unknown) =>
        err instanceof GitHubApiError && err.status === 403 && /Resource not accessible/.test(err.message),
    );
  });
});
