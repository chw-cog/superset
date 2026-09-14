/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
import { sanitizeUrl } from '@braintree/sanitize-url';
import callApiAndParseWithTimeout from './callApi/callApiAndParseWithTimeout';
import {
  ClientConfig,
  ClientTimeout,
  Credentials,
  CsrfPromise,
  CsrfToken,
  FetchRetryOptions,
  Headers,
  Host,
  Mode,
  Protocol,
  RequestConfig,
  ParseMethod,
} from './types';
import { DEFAULT_FETCH_RETRY_OPTIONS, DEFAULT_APP_ROOT } from './constants';

const CSRF_HEADER = 'X-CSRFToken';
// Mirrors `SupersetErrorType.FRONTEND_CSRF_ERROR`, emitted by the server when
// a JSON request is rejected at CSRF validation (before the view runs).
const CSRF_ERROR_TYPE = 'FRONTEND_CSRF_ERROR';

async function isCsrfRejection(res: unknown): Promise<boolean> {
  if (typeof res !== 'object' || res === null) {
    return false;
  }
  const { status, clone } = res as Partial<Response>;
  if (status !== 400 || typeof clone !== 'function') {
    return false;
  }
  try {
    const body: unknown = await clone.call(res).json();
    if (typeof body !== 'object' || body === null || !('errors' in body)) {
      return false;
    }
    const { errors } = body as { errors: unknown };
    return (
      Array.isArray(errors) &&
      errors.some(
        (error: unknown) =>
          typeof error === 'object' &&
          error !== null &&
          (error as { error_type?: unknown }).error_type === CSRF_ERROR_TYPE,
      )
    );
  } catch {
    return false;
  }
}

const defaultUnauthorizedHandlerForPrefix = (appRoot: string) => () => {
  if (!window.location.pathname.startsWith(`${appRoot}/login`)) {
    window.location.href = `${appRoot}/login?next=${window.location.href}`;
  }
};

export default class SupersetClientClass {
  credentials: Credentials;

  csrfToken?: CsrfToken;

  csrfPromise?: CsrfPromise;

  csrfRefreshPromise?: CsrfPromise;

  guestToken?: string;

  guestTokenHeaderName: string;

  fetchRetryOptions?: FetchRetryOptions;

  appRoot?: string;

  protocol: Protocol;

  host: Host;

  headers: Headers;

  mode: Mode;

  timeout: ClientTimeout;

  handleUnauthorized: () => void;

  constructor({
    host,
    protocol,
    appRoot = DEFAULT_APP_ROOT,
    headers = {},
    fetchRetryOptions = {},
    mode = 'same-origin',
    timeout,
    credentials = undefined,
    csrfToken = undefined,
    guestToken = undefined,
    guestTokenHeaderName = 'X-GuestToken',
    unauthorizedHandler = undefined,
  }: ClientConfig = {}) {
    const url = new URL(`${protocol || 'https:'}//${host || 'localhost'}`);
    // Strip a trailing slash so the getUrl dedupe comparisons and the final
    // `${this.appRoot}/${...}` build stay correct regardless of how the root
    // was supplied. Mirrors normalizeBackendUrlString / AppRootMiddleware /
    // LegacyPrefixRedirectMiddleware, which all rstrip the root.
    this.appRoot = appRoot.replace(/\/$/, '');
    this.host = url.host;
    this.protocol = url.protocol as Protocol;
    this.headers = { Accept: 'application/json', ...headers }; // defaulting accept to json
    this.mode = mode;
    this.timeout = timeout;
    this.credentials = credentials;
    this.csrfToken = csrfToken;
    this.guestToken = guestToken;
    this.guestTokenHeaderName = guestTokenHeaderName;
    this.fetchRetryOptions = {
      ...DEFAULT_FETCH_RETRY_OPTIONS,
      ...fetchRetryOptions,
    };
    if (typeof this.csrfToken === 'string') {
      this.headers = { ...this.headers, [CSRF_HEADER]: this.csrfToken };
      this.csrfPromise = Promise.resolve(this.csrfToken);
    }
    if (guestToken) {
      this.headers[guestTokenHeaderName] = guestToken;
    }
    this.handleUnauthorized =
      unauthorizedHandler !== undefined
        ? unauthorizedHandler
        : defaultUnauthorizedHandlerForPrefix(this.appRoot);
  }

  async init(force = false): CsrfPromise {
    if (this.isAuthenticated() && !force) {
      return this.csrfPromise as CsrfPromise;
    }
    return this.fetchCSRFToken();
  }

  async postForm(
    endpoint: string,
    payload: Record<string, any>,
    target = '_blank',
  ) {
    if (endpoint) {
      await this.ensureAuth();
      const hiddenForm = document.createElement('form');
      hiddenForm.action = sanitizeUrl(this.getUrl({ endpoint }));
      hiddenForm.method = 'POST';
      hiddenForm.target = target;
      const payloadWithToken: Record<string, any> = {
        ...payload,
        csrf_token: this.csrfToken!,
      };

      if (this.guestToken) {
        payloadWithToken.guest_token = this.guestToken;
      }

      Object.entries(payloadWithToken).forEach(([key, value]) => {
        const data = document.createElement('input');
        data.type = 'hidden';
        data.name = key;
        data.value = value;
        hiddenForm.appendChild(data);
      });

      document.body.appendChild(hiddenForm);
      hiddenForm.submit();
      document.body.removeChild(hiddenForm);
    }
  }

  /**
   * POST request that returns a blob for file downloads.
   * Unlike postForm, this uses AJAX so errors can be caught and handled.
   * @param endpoint - API endpoint
   * @param payload - Request payload
   * @returns Promise resolving to Response with blob
   */
  async postBlob(
    endpoint: string,
    payload: Record<string, any>,
  ): Promise<Response> {
    await this.ensureAuth();
    return this.post({
      endpoint,
      postPayload: payload,
      parseMethod: 'raw',
      stringify: false,
    });
  }

  async reAuthenticate() {
    return this.init(true);
  }

  isAuthenticated(): boolean {
    // if CSRF protection is disabled in the Superset app, the token may be an empty string
    return this.csrfToken !== null && this.csrfToken !== undefined;
  }

  getGuestToken() {
    return this.guestToken;
  }

  async get<T extends ParseMethod = 'json'>(
    requestConfig: RequestConfig & { parseMethod?: T },
  ) {
    return this.request({ ...requestConfig, method: 'GET' });
  }

  async delete<T extends ParseMethod = 'json'>(
    requestConfig: RequestConfig & { parseMethod?: T },
  ) {
    return this.request({ ...requestConfig, method: 'DELETE' });
  }

  async put<T extends ParseMethod = 'json'>(
    requestConfig: RequestConfig & { parseMethod?: T },
  ) {
    return this.request({ ...requestConfig, method: 'PUT' });
  }

  async post<T extends ParseMethod = 'json'>(
    requestConfig: RequestConfig & { parseMethod?: T },
  ) {
    return this.request({ ...requestConfig, method: 'POST' });
  }

  async request<T extends ParseMethod = 'json'>(
    requestConfig: RequestConfig & { parseMethod?: T },
  ) {
    await this.ensureAuth();
    return this.requestWithCsrfRecovery(requestConfig, true);
  }

  private async requestWithCsrfRecovery<T extends ParseMethod = 'json'>(
    requestConfig: RequestConfig & { parseMethod?: T },
    allowCsrfRetry: boolean,
  ): ReturnType<typeof callApiAndParseWithTimeout<T>> {
    const {
      credentials,
      mode,
      endpoint,
      host,
      url,
      headers,
      timeout,
      fetchRetryOptions,
      ignoreUnauthorized = false,
      ...rest
    } = requestConfig;
    const tokenUsed = this.csrfToken;
    return callApiAndParseWithTimeout({
      ...rest,
      credentials: credentials ?? this.credentials,
      mode: mode ?? this.mode,
      url: this.getUrl({ endpoint, host, url }),
      headers: { ...this.headers, ...headers },
      timeout: timeout ?? this.timeout,
      fetchRetryOptions: fetchRetryOptions ?? this.fetchRetryOptions,
    }).catch(async (res: unknown) => {
      if (
        (res as Partial<Response> | null)?.status === 401 &&
        !ignoreUnauthorized
      ) {
        this.handleUnauthorized();
      }
      if (!allowCsrfRetry || !(await isCsrfRejection(res))) {
        return Promise.reject(res);
      }
      try {
        await this.refreshCsrfTokenAfterRejection(tokenUsed);
      } catch {
        return Promise.reject(res);
      }
      // Drop any explicitly supplied CSRF header so the replay uses the
      // freshly fetched token from `this.headers` instead of the stale one.
      const freshHeaders = { ...headers };
      delete freshHeaders[CSRF_HEADER];
      return this.requestWithCsrfRecovery(
        { ...requestConfig, headers: freshHeaders },
        false,
      );
    });
  }

  /**
   * Refresh the CSRF token after the server rejected a request that carried
   * `staleToken`. Concurrent rejections share a single in-flight refresh, and
   * a rejection that arrives after the token has already been replaced does
   * not trigger another round trip.
   */
  private async refreshCsrfTokenAfterRejection(
    staleToken: CsrfToken | undefined,
  ): CsrfPromise {
    if (this.csrfRefreshPromise) {
      return this.csrfRefreshPromise;
    }
    if (this.isAuthenticated() && this.csrfToken !== staleToken) {
      return this.csrfToken;
    }
    this.csrfRefreshPromise = this.fetchCSRFToken().finally(() => {
      this.csrfRefreshPromise = undefined;
    });
    return this.csrfRefreshPromise;
  }

  async ensureAuth(): CsrfPromise {
    return (
      this.csrfPromise ??
      // eslint-disable-next-line prefer-promise-reject-errors
      Promise.reject({
        error: `SupersetClient has not been provided a CSRF token, ensure it is
        initialized with \`client.getCSRFToken()\` or try logging in at
        ${this.getUrl({ endpoint: '/login' })}`,
      })
    );
  }

  async fetchCSRFToken() {
    this.csrfToken = undefined;
    // If we can request this resource successfully, it means that the user has
    // authenticated. If not we throw an error prompting to authenticate.
    this.csrfPromise = callApiAndParseWithTimeout({
      credentials: this.credentials,
      headers: {
        ...this.headers,
      },
      method: 'GET',
      mode: this.mode,
      timeout: this.timeout,
      url: this.getUrl({ endpoint: '/api/v1/security/csrf_token/' }),
      parseMethod: 'json',
    }).then(({ json }) => {
      if (typeof json === 'object') {
        this.csrfToken = json.result as string;
        if (typeof this.csrfToken === 'string') {
          this.headers = { ...this.headers, [CSRF_HEADER]: this.csrfToken };
        }
      }
      if (this.isAuthenticated()) {
        return this.csrfToken;
      }
      // eslint-disable-next-line prefer-promise-reject-errors
      return Promise.reject({ error: 'Failed to fetch CSRF token' });
    });
    return this.csrfPromise;
  }

  async getCSRFToken() {
    return this.csrfToken || this.fetchCSRFToken();
  }

  getUrl({
    host: inputHost,
    endpoint = '',
    url,
  }: {
    endpoint?: string;
    host?: Host;
    url?: string;
  } = {}) {
    if (typeof url === 'string') return url;

    const host = inputHost ?? this.host;
    const cleanHost = host.slice(-1) === '/' ? host.slice(0, -1) : host; // no backslash

    // Strip a single leading appRoot segment so callers that accidentally
    // pre-prefix their endpoint (e.g. by wrapping with ensureAppRoot before
    // passing to the client) do not produce a doubled `/superset/superset/...`
    // URL. Single-pass strip mirrors
    // `stripAppRoot` in `src/utils/pathUtils` and `normalizeBackendUrlString`
    // exactly: a genuine `/superset/superset/<slug>` is a legitimate route, not
    // a double-prefix bug. The L2 static invariant still flags pre-prefixing as
    // a migration issue; this is the runtime safety net.
    let cleanEndpoint = endpoint;
    const root = this.appRoot;
    if (root) {
      if (cleanEndpoint === root) {
        cleanEndpoint = '';
      } else if (cleanEndpoint.startsWith(`${root}/`)) {
        cleanEndpoint = cleanEndpoint.slice(root.length);
      }
    }

    return `${this.protocol}//${cleanHost}${this.appRoot}/${
      cleanEndpoint[0] === '/' ? cleanEndpoint.slice(1) : cleanEndpoint
    }`;
  }
}
