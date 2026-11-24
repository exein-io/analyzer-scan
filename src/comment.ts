/**
 * The comment on the pull request: one per pull request and object, found again by a hidden marker and
 * updated on each run. Posted with the workflow's own token, by GitHub's REST API.
 */

/** The events whose payload names a pull request to comment on. */
export const PR_EVENTS = ['pull_request', 'pull_request_target'] as const;

/** GitHub refuses a comment body longer than this. */
export const MAX_COMMENT_LENGTH = 65_536;

export interface IssueComment {
  id: number;
  body?: string | null;
  user?: { type?: string } | null;
  /** How the author relates to the repository: `OWNER`, `MEMBER`, `COLLABORATOR`, `CONTRIBUTOR`, `NONE`, ... */
  author_association?: string;
}

/** The authors whose comments with the marker the action takes over: no outside contributor. */
const TRUSTED_ASSOCIATIONS = ['OWNER', 'MEMBER', 'COLLABORATOR'];

/**
 * A comment the action may update: one by a bot, as with the workflow token, or by someone with write access,
 * as with a personal token. Anyone can paste the marker, so a comment by anyone else is never adopted.
 */
export function isOwnComment(c: IssueComment): boolean {
  return c.user?.type === 'Bot' || TRUSTED_ASSOCIATIONS.includes(c.author_association ?? '');
}

/** The calls the comment needs, so tests replace GitHub's API. */
export interface CommentApi {
  /** Every comment of the pull request, oldest first. */
  listComments(issueNumber: number): Promise<IssueComment[]>;
  createComment(issueNumber: number, body: string): Promise<void>;
  updateComment(commentId: number, body: string): Promise<void>;
  /** The commit the pull request is at now. */
  headSha(pullNumber: number): Promise<string | undefined>;
}

/** The hidden line that tells this comment from the others: one per object, so each scan step keeps its own. */
export function commentMarker(key: string): string {
  // An HTML comment ends at `--`, so the key is percent-encoded, a hyphen before another hyphen too. Encoding
  // keeps two keys apart, where replacing their characters would give both one marker and one comment.
  const safe = encodeURIComponent(key).replace(/-(?=-)/g, '%2D');
  return `<!-- exein-analyzer-scan:${safe} -->`;
}

/** The number of the pull request of the event, or undefined outside a pull request event. */
export function pullRequestNumber(eventName: string | undefined, payload: unknown): number | undefined {
  if (!PR_EVENTS.includes(eventName as (typeof PR_EVENTS)[number])) {
    return undefined;
  }
  const number = (payload as { pull_request?: { number?: unknown } } | undefined)?.pull_request?.number;
  return typeof number === 'number' ? number : undefined;
}

/** The marker first, so the comment is found again; the body cut to what GitHub takes. */
export function commentBody(key: string, body: string, footer?: string): string {
  const head = `${commentMarker(key)}\n`;
  const tail = footer ? `\n${footer}\n` : '';
  const room = MAX_COMMENT_LENGTH - head.length - tail.length;
  const cut = '\n\n(cut to fit a comment: the job summary has it all)\n';
  const text = body.length > room ? body.slice(0, room - cut.length) + cut : body;
  return head + text + tail;
}

/**
 * Updates the comment that carries the marker of `key`, or makes it. With `sha`, the commit the run gated,
 * skips when the pull request has moved on, so a run that ends late does not cover a newer run's result.
 */
export async function upsertComment(
  api: CommentApi,
  issueNumber: number,
  key: string,
  body: string,
  sha?: string,
): Promise<'created' | 'updated' | 'skipped'> {
  if (sha) {
    const head = await api.headSha(issueNumber);
    if (head && head !== sha) {
      return 'skipped';
    }
  }
  const marker = commentMarker(key);
  const comments = await api.listComments(issueNumber);
  const previous = comments.find((c) => c.body?.startsWith(marker) && isOwnComment(c));
  if (previous) {
    await api.updateComment(previous.id, body);
    return 'updated';
  }
  await api.createComment(issueNumber, body);
  return 'created';
}

export interface RestApiOptions {
  /** `GITHUB_API_URL`, such as `https://api.github.com`. */
  apiUrl: string;
  /** `owner/repo`, as `GITHUB_REPOSITORY`. */
  repository: string;
  token: string;
  fetch?: typeof fetch;
}

/** The longest list of comments read: 100 pages of 100. */
const MAX_PAGES = 100;

/** How long one request to GitHub may take, so an API that hangs does not hold the step. */
const REQUEST_TIMEOUT_MS = 30_000;

/** GitHub's REST API for issue comments, by `fetch`, so the action needs no client library. */
export function restCommentApi({
  apiUrl,
  repository,
  token,
  fetch: doFetch = fetch,
}: RestApiOptions): CommentApi {
  const repo = `${apiUrl.replace(/\/+$/, '')}/repos/${repository}`;
  const base = `${repo}/issues`;
  const pulls = `${repo}/pulls`;
  const request = async (method: string, url: string, body?: unknown): Promise<unknown> => {
    const res = await doFetch(url, {
      method,
      headers: {
        Accept: 'application/vnd.github+json',
        Authorization: `Bearer ${token}`,
        'X-GitHub-Api-Version': '2022-11-28',
        'User-Agent': 'exein-analyzer-scan',
        ...(body === undefined ? {} : { 'Content-Type': 'application/json' }),
      },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });
    if (!res.ok) {
      const text = (await res.text().catch(() => '')).slice(0, 300);
      throw new GitHubApiError(
        res.status,
        `${method} ${url} answered ${res.status}${text ? `: ${text}` : ''}`,
      );
    }
    return method === 'GET' ? res.json() : undefined;
  };
  return {
    async listComments(issueNumber) {
      const all: IssueComment[] = [];
      for (let page = 1; page <= MAX_PAGES; page++) {
        const batch = (await request(
          'GET',
          `${base}/${issueNumber}/comments?per_page=100&page=${page}`,
        )) as IssueComment[];
        all.push(...batch);
        if (batch.length < 100) {
          break;
        }
      }
      return all;
    },
    async createComment(issueNumber, body) {
      await request('POST', `${base}/${issueNumber}/comments`, { body });
    },
    async headSha(pullNumber) {
      const pr = (await request('GET', `${pulls}/${pullNumber}`)) as { head?: { sha?: unknown } };
      return typeof pr.head?.sha === 'string' ? pr.head.sha : undefined;
    },
    async updateComment(commentId, body) {
      await request('PATCH', `${base}/comments/${commentId}`, { body });
    },
  };
}

export class GitHubApiError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
    this.name = 'GitHubApiError';
  }
}

/** The warning for a comment that failed. The step goes on. */
export function commentWarning(err: unknown): string {
  const message = err instanceof Error ? err.message : String(err);
  const hint =
    err instanceof GitHubApiError && (err.status === 401 || err.status === 403 || err.status === 404)
      ? ". The token needs the pull-requests: write permission; a pull request from a fork gets a read-only token. Set pr-comment: 'false' to turn the comment off"
      : '';
  return `Could not comment on the pull request: ${message}${hint}`;
}
