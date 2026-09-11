(function initializeRequestInterceptionCore(root, factory) {
  const core = factory();

  root.EnhancedNetworkTab = root.EnhancedNetworkTab || {};
  root.EnhancedNetworkTab.RequestInterceptionCore = core;

  if (typeof module === 'object' && module.exports) {
    module.exports = core;
  }
})(typeof globalThis !== 'undefined' ? globalThis : this, function createRequestInterceptionCore() {
  'use strict';

  const MODIFIED_REQUEST_ACTIONS = Object.freeze({
    REPEATER_DRAFT: 'repeater-draft',
    CANCEL_AND_SEND: 'cancel-and-send'
  });
  const PROMOTION_ID = 'experimental-intercept-v1';
  const HTTP_HEADER_NAME = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;
  const INVALID_HEADER_VALUE = /[\u0000-\u0008\u000A-\u001F\u007F]/;
  const SENSITIVE_HEADERS = new Set([
    'authorization',
    'cookie',
    'host',
    'origin',
    'referer',
    'proxy-authorization'
  ]);

  function normalizeModifiedRequestAction(value) {
    return value === MODIFIED_REQUEST_ACTIONS.CANCEL_AND_SEND
      ? MODIFIED_REQUEST_ACTIONS.CANCEL_AND_SEND
      : MODIFIED_REQUEST_ACTIONS.REPEATER_DRAFT;
  }

  function normalizeHeaders(headers) {
    if (!Array.isArray(headers)) return [];
    return headers
      .filter(header => header && header.name !== undefined)
      .map(header => ({
        name: String(header.name),
        value: String(header.value ?? '')
      }));
  }

  function headersEqual(first, second) {
    const left = normalizeHeaders(first);
    const right = normalizeHeaders(second);
    if (left.length !== right.length) return false;
    return left.every((header, index) =>
      header.name === right[index].name && header.value === right[index].value
    );
  }

  function getRequestEdits(pending, modifiedRequest) {
    if (!modifiedRequest) {
      return {
        urlChanged: false,
        methodChanged: false,
        headersChanged: false,
        bodyChanged: false,
        anyChanged: false
      };
    }

    const edits = {
      urlChanged: modifiedRequest.url !== pending.url,
      methodChanged: modifiedRequest.method !== pending.method,
      headersChanged: !headersEqual(modifiedRequest.headers, pending.requestHeaders),
      bodyChanged: modifiedRequest.body !== pending.requestBody
    };
    edits.anyChanged = edits.urlChanged || edits.methodChanged ||
      edits.headersChanged || edits.bodyChanged;
    return edits;
  }

  function decodedBase64Length(value) {
    const compact = String(value ?? '').replace(/\s+/g, '');
    if (compact === '') return 0;
    if (compact.length % 4 !== 0) return null;
    if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(compact)) {
      return null;
    }

    const padding = compact.endsWith('==') ? 2 : compact.endsWith('=') ? 1 : 0;
    return (compact.length / 4) * 3 - padding;
  }

  function textByteLength(value) {
    return new TextEncoder().encode(String(value ?? '')).byteLength;
  }

  function validateEditedUrl(requestData) {
    const errors = [];
    let parsedUrl = null;

    try {
      parsedUrl = new URL(String(requestData?.url || ''));
      if (parsedUrl.protocol !== 'http:' && parsedUrl.protocol !== 'https:') {
        errors.push({ field: 'url', code: 'unsupported-protocol', message: 'Only HTTP and HTTPS URLs can be sent.' });
      }
    } catch (_) {
      errors.push({ field: 'url', code: 'invalid-url', message: 'Enter a valid HTTP or HTTPS URL.' });
    }

    return { valid: errors.length === 0, errors, parsedUrl };
  }

  function validateEditedHeaders(requestData) {
    const errors = [];

    if (requestData?.headersText !== undefined) {
      for (const [index, line] of String(requestData.headersText).split(/\r?\n/).entries()) {
        if (!line.trim()) continue;
        const separator = line.indexOf(':');
        if (separator <= 0) {
          errors.push({
            field: 'headers',
            code: 'malformed-header-line',
            message: `Header line ${index + 1} must use the “Name: value” format.`
          });
        }
      }
    }

    if (requestData?.headers !== undefined && !Array.isArray(requestData.headers)) {
      errors.push({
        field: 'headers',
        code: 'invalid-header-list',
        message: 'Headers must be provided as an ordered list.'
      });
    }

    if (Array.isArray(requestData?.headers)) {
      for (const header of requestData.headers) {
        if (!header || header.name === undefined) {
          errors.push({
            field: 'headers',
            code: 'invalid-header-entry',
            message: 'Every header entry must include a name.'
          });
        }
      }
    }

    const headers = normalizeHeaders(requestData?.headers);
    for (const header of headers) {
      if (!HTTP_HEADER_NAME.test(header.name)) {
        errors.push({ field: 'headers', code: 'invalid-header-name', message: `Invalid header name: ${header.name || '(empty)'}` });
      }
      if (INVALID_HEADER_VALUE.test(header.value)) {
        errors.push({ field: 'headers', code: 'invalid-header-value', message: `Header ${header.name || '(empty)'} contains unsupported control characters.` });
      }
    }

    return { valid: errors.length === 0, errors };
  }

  function validateEditedRequest(requestData, options = {}) {
    const maxBodyBytes = Number.isFinite(options.maxBodyBytes)
      ? options.maxBodyBytes
      : Number.POSITIVE_INFINITY;
    const urlValidation = validateEditedUrl(requestData);
    const headerValidation = validateEditedHeaders(requestData);
    const errors = [...urlValidation.errors, ...headerValidation.errors];

    const method = String(requestData?.method || 'GET').toUpperCase();
    if (!HTTP_HEADER_NAME.test(method)) {
      errors.push({ field: 'method', code: 'invalid-method', message: 'Enter a valid HTTP method.' });
    } else if (['CONNECT', 'TRACE', 'TRACK'].includes(method)) {
      errors.push({
        field: 'method',
        code: 'forbidden-method',
        message: `${method} cannot be sent by the extension request API.`
      });
    }

    const body = requestData?.body;
    const hasNonEmptyBody = body !== undefined && body !== null && String(body) !== '';
    if ((method === 'GET' || method === 'HEAD') && hasNonEmptyBody) {
      errors.push({ field: 'body', code: 'method-disallows-body', message: `${method} requests cannot be sent with a body.` });
    }

    if (requestData?.bodyReplayable === false) {
      errors.push({ field: 'body', code: 'body-unavailable', message: requestData.bodyUnavailableReason || 'The captured request body cannot be replayed safely.' });
    }

    let bodyByteLength = 0;
    if (body !== undefined && body !== null) {
      if (requestData.bodyEncoding === 'base64') {
        bodyByteLength = decodedBase64Length(body);
        if (bodyByteLength === null) {
          errors.push({ field: 'body', code: 'invalid-base64', message: 'The request body is not valid Base64.' });
        }
      } else if (requestData.bodyEncoding === undefined ||
                 requestData.bodyEncoding === 'text') {
        bodyByteLength = textByteLength(body);
      } else {
        bodyByteLength = null;
        errors.push({
          field: 'body',
          code: 'unsupported-body-encoding',
          message: 'The request body encoding must be text or Base64.'
        });
      }
    }

    if (bodyByteLength !== null && bodyByteLength > maxBodyBytes) {
      errors.push({ field: 'body', code: 'body-too-large', message: `The request body exceeds the ${maxBodyBytes}-byte replay limit.` });
    }

    return {
      valid: errors.length === 0,
      errors,
      parsedUrl: urlValidation.parsedUrl,
      bodyByteLength
    };
  }

  function validateEditedResponse(responseData, options = {}) {
    const maxBodyBytes = Number.isFinite(options.maxBodyBytes)
      ? options.maxBodyBytes
      : Number.POSITIVE_INFINITY;
    const errors = [];

    if (responseData?.headersEdited) {
      const headerValidation = validateEditedHeaders(responseData);
      errors.push(...headerValidation.errors);
    }

    let bodyByteLength = 0;
    if (responseData?.bodyEdited) {
      if (responseData.bodyEncoding === 'base64') {
        bodyByteLength = decodedBase64Length(responseData.body);
        if (bodyByteLength === null) {
          errors.push({
            field: 'body',
            code: 'invalid-base64',
            message: 'The response body is not valid Base64.'
          });
        }
      } else if (responseData.bodyEncoding === undefined ||
                 responseData.bodyEncoding === 'text') {
        bodyByteLength = textByteLength(responseData.body);
      } else {
        bodyByteLength = null;
        errors.push({
          field: 'body',
          code: 'unsupported-body-encoding',
          message: 'The response body encoding must be text or Base64.'
        });
      }

      if (bodyByteLength !== null && bodyByteLength > maxBodyBytes) {
        errors.push({
          field: 'body',
          code: 'body-too-large',
          message: `The response body exceeds the ${maxBodyBytes}-byte edit limit.`
        });
      }
    }

    return {
      valid: errors.length === 0,
      errors,
      bodyByteLength
    };
  }

  function decideInterceptAction(pending, modifiedRequest, options = {}) {
    const edits = getRequestEdits(pending, modifiedRequest);
    const mode = normalizeModifiedRequestAction(options.modifiedRequestAction);
    const earlyStage = pending.stage === 'onBeforeRequest';

    if (modifiedRequest?.headersText !== undefined) {
      const validation = validateEditedHeaders(modifiedRequest);
      if (!validation.valid) {
        return { action: 'reject-edit', edits, validation };
      }
    }

    if (!edits.anyChanged) {
      return { action: 'forward', edits };
    }

    if (earlyStage) {
      if (edits.methodChanged || edits.bodyChanged) {
        return { action: 'create-repeater-draft', edits, reason: 'early-stage-replay' };
      }
      if (edits.urlChanged) {
        const validation = validateEditedUrl(modifiedRequest);
        return validation.valid
          ? { action: 'redirect', edits, validation }
          : { action: 'reject-edit', edits, validation };
      }
      return { action: 'forward', edits };
    }

    const requiresExtensionRequest = edits.urlChanged || edits.methodChanged || edits.bodyChanged;
    if (requiresExtensionRequest) {
      if (mode !== MODIFIED_REQUEST_ACTIONS.CANCEL_AND_SEND) {
        return { action: 'create-repeater-draft', edits };
      }

      const validation = validateEditedRequest(modifiedRequest, options);
      if (!validation.valid) {
        return { action: 'reject-edit', edits, validation };
      }
      return { action: 'cancel-and-send', edits, validation };
    }

    if (edits.headersChanged) {
      const validation = validateEditedHeaders(modifiedRequest);
      return validation.valid
        ? { action: 'apply-headers', edits, validation }
        : { action: 'reject-edit', edits, validation };
    }

    return { action: 'forward', edits };
  }

  function getCrossOriginSensitiveHeaders(originalUrl, modifiedUrl, headers) {
    let originalOrigin;
    let modifiedOrigin;
    try {
      originalOrigin = new URL(originalUrl).origin;
      modifiedOrigin = new URL(modifiedUrl).origin;
    } catch (_) {
      return { crossOrigin: false, originalOrigin: '', modifiedOrigin: '', headerNames: [] };
    }

    const names = [];
    const seenNames = new Set();
    if (originalOrigin !== modifiedOrigin) {
      for (const header of normalizeHeaders(headers)) {
        const normalizedName = header.name.toLowerCase();
        if (SENSITIVE_HEADERS.has(normalizedName) && !seenNames.has(normalizedName)) {
          seenNames.add(normalizedName);
          names.push(header.name);
        }
      }
    }

    return {
      crossOrigin: originalOrigin !== modifiedOrigin,
      originalOrigin,
      modifiedOrigin,
      headerNames: names
    };
  }

  function sanitizeHeadersForRedirect(initialUrl, currentUrl, headers) {
    let initialOrigin;
    let currentOrigin;
    try {
      initialOrigin = new URL(initialUrl).origin;
      currentOrigin = new URL(currentUrl).origin;
    } catch (_) {
      return normalizeHeaders(headers);
    }
    if (initialOrigin === currentOrigin) return normalizeHeaders(headers);

    const strippedHeaders = new Set([
      'authorization',
      'cookie',
      'host',
      'origin',
      'proxy-authorization',
      'referer'
    ]);
    return normalizeHeaders(headers).filter(header =>
      !strippedHeaders.has(header.name.toLowerCase())
    );
  }

  function shouldQueuePromotion(details, seenPromotionIds, promotionId = PROMOTION_ID) {
    return details?.reason === 'update' &&
      !new Set(Array.isArray(seenPromotionIds) ? seenPromotionIds : []).has(promotionId);
  }

  function claimPromotionState(
    pendingPromotionId,
    seenPromotionIds,
    modifiedRequestAction,
    promotionId = PROMOTION_ID
  ) {
    const seen = Array.isArray(seenPromotionIds)
      ? Array.from(new Set(seenPromotionIds))
      : [];
    if (pendingPromotionId !== promotionId) {
      return { pendingPromotionId, seenPromotionIds: seen, promotion: null };
    }
    if (seen.includes(promotionId)) {
      return { pendingPromotionId: null, seenPromotionIds: seen, promotion: null };
    }
    if (!seen.includes(promotionId)) seen.push(promotionId);
    return {
      pendingPromotionId: null,
      seenPromotionIds: seen,
      promotion: normalizeModifiedRequestAction(modifiedRequestAction) ===
        MODIFIED_REQUEST_ACTIONS.CANCEL_AND_SEND
        ? null
        : { id: promotionId }
    };
  }

  function createSingleStartGuard(startAction) {
    let started = false;
    return function startOnce(reason) {
      if (started) return false;
      started = true;
      startAction(reason);
      return true;
    };
  }

  function createExtensionRequestChainTracker() {
    const extensionRequestIds = new Map();
    return {
      track(browserRequestId, extensionRequestId) {
        extensionRequestIds.set(browserRequestId, extensionRequestId);
      },
      get(browserRequestId) {
        return extensionRequestIds.get(browserRequestId) || null;
      },
      clear(browserRequestId) {
        return extensionRequestIds.delete(browserRequestId);
      },
      clearExtension(extensionRequestId) {
        let cleared = 0;
        for (const [browserRequestId, trackedExtensionRequestId] of extensionRequestIds) {
          if (trackedExtensionRequestId !== extensionRequestId) continue;
          extensionRequestIds.delete(browserRequestId);
          cleared += 1;
        }
        return cleared;
      }
    };
  }

  function createRuleRedirectTracker(options = {}) {
    const maxVisitedUrls = Number.isInteger(options.maxVisitedUrls)
      ? Math.max(1, options.maxVisitedUrls)
      : 32;
    const maxAppliedRules = Number.isInteger(options.maxAppliedRules)
      ? Math.max(1, options.maxAppliedRules)
      : 128;
    const states = new Map();

    function begin(browserRequestId, url, tabId = null) {
      let state = states.get(browserRequestId);
      if (!state) {
        state = {
          tabId,
          visitedUrls: new Set(),
          appliedRules: new Set()
        };
        states.set(browserRequestId, state);
      }
      if (state.tabId === null && tabId !== null) state.tabId = tabId;
      if (state.visitedUrls.size < maxVisitedUrls) {
        state.visitedUrls.add(String(url));
      }
      return state;
    }

    function tryRedirect(browserRequestId, ruleKey, currentUrl, nextUrl, tabId = null) {
      const state = begin(browserRequestId, currentUrl, tabId);
      const normalizedRuleKey = String(ruleKey);
      const normalizedNextUrl = String(nextUrl);

      if (state.appliedRules.has(normalizedRuleKey)) {
        return { allowed: false, reason: 'rule-already-applied' };
      }
      if (state.appliedRules.size >= maxAppliedRules) {
        return { allowed: false, reason: 'rule-limit' };
      }

      state.appliedRules.add(normalizedRuleKey);
      if (state.visitedUrls.has(normalizedNextUrl)) {
        return { allowed: false, reason: 'visited-url' };
      }
      if (state.visitedUrls.size >= maxVisitedUrls) {
        return { allowed: false, reason: 'redirect-limit' };
      }

      state.visitedUrls.add(normalizedNextUrl);
      return { allowed: true, reason: 'redirect-recorded' };
    }

    function clear(browserRequestId) {
      return states.delete(browserRequestId);
    }

    function clearTab(tabId) {
      let cleared = 0;
      for (const [browserRequestId, state] of states) {
        if (state.tabId !== tabId) continue;
        states.delete(browserRequestId);
        cleared += 1;
      }
      return cleared;
    }

    return {
      begin,
      clear,
      clearTab,
      size: () => states.size,
      tryRedirect
    };
  }

  function createBoundedResultStore(options = {}) {
    const maxEntries = Number.isInteger(options.maxEntries)
      ? Math.max(1, options.maxEntries)
      : 25;
    const maxBytes = Number.isFinite(options.maxBytes)
      ? Math.max(1, options.maxBytes)
      : 10 * 1024 * 1024;
    const estimateSize = typeof options.estimateSize === 'function'
      ? options.estimateSize
      : value => new TextEncoder().encode(JSON.stringify(value ?? null)).byteLength;
    const entries = new Map();
    let totalBytes = 0;

    function remove(key) {
      const existing = entries.get(key);
      if (!existing) return false;
      entries.delete(key);
      totalBytes -= existing.size;
      return true;
    }

    function set(key, value) {
      remove(key);
      const size = Math.max(0, Number(estimateSize(value)) || 0);
      if (size > maxBytes) return false;

      entries.set(key, { value, size });
      totalBytes += size;
      while (entries.size > maxEntries || totalBytes > maxBytes) {
        const oldestKey = entries.keys().next().value;
        if (oldestKey === undefined) break;
        remove(oldestKey);
      }
      return entries.has(key);
    }

    function get(key) {
      const entry = entries.get(key);
      if (!entry) return null;
      // Refresh insertion order so recently opened results survive eviction.
      entries.delete(key);
      entries.set(key, entry);
      return entry.value;
    }

    function clear() {
      entries.clear();
      totalBytes = 0;
    }

    return {
      clear,
      delete: remove,
      get,
      has: key => entries.has(key),
      set,
      size: () => entries.size,
      totalBytes: () => totalBytes
    };
  }

  function createReplacementStartController(startAction, failAction) {
    let state = 'pending';
    return {
      confirm(reason) {
        if (state !== 'pending') return false;
        state = 'started';
        startAction(reason);
        return true;
      },
      fail(reason) {
        if (state !== 'pending') return false;
        state = 'failed';
        failAction(reason);
        return true;
      },
      getState() {
        return state;
      }
    };
  }

  return {
    MODIFIED_REQUEST_ACTIONS,
    PROMOTION_ID,
    claimPromotionState,
    createBoundedResultStore,
    createExtensionRequestChainTracker,
    createRuleRedirectTracker,
    createReplacementStartController,
    createSingleStartGuard,
    decideInterceptAction,
    decodedBase64Length,
    getCrossOriginSensitiveHeaders,
    getRequestEdits,
    normalizeModifiedRequestAction,
    sanitizeHeadersForRedirect,
    shouldQueuePromotion,
    validateEditedHeaders,
    validateEditedRequest,
    validateEditedResponse,
    validateEditedUrl
  };
});
