(function initializeHarMatcherCore(root, factory) {
  const core = factory();

  root.EnhancedNetworkTab = root.EnhancedNetworkTab || {};
  root.EnhancedNetworkTab.HarMatcherCore = core;

  if (typeof module === 'object' && module.exports) {
    module.exports = core;
  }
})(typeof globalThis !== 'undefined' ? globalThis : this, function createHarMatcherCore() {
  'use strict';

  function stableHash(value) {
    const text = String(value ?? '');
    let hash = 2166136261;
    for (let index = 0; index < text.length; index += 1) {
      hash ^= text.charCodeAt(index);
      hash = Math.imul(hash, 16777619);
    }
    return (hash >>> 0).toString(16);
  }

  function harBodyText(entry) {
    const postData = entry.request?.postData;
    if (!postData) return null;
    if (typeof postData.text === 'string') return postData.text;
    if (Array.isArray(postData.params)) {
      return postData.params
        .map(parameter => `${encodeURIComponent(parameter.name)}=${encodeURIComponent(parameter.value || '')}`)
        .join('&');
    }
    return null;
  }

  function fingerprint(entry) {
    return [
      entry.request?.method || '',
      entry.request?.url || '',
      entry.startedDateTime || '',
      entry.response?.status ?? '',
      entry.response?.bodySize ?? entry.response?.content?.size ?? '',
      stableHash(harBodyText(entry))
    ].join('|');
  }

  function createMatcher({ maxTimeDifferenceMs = 30_000 } = {}) {
    const processedFingerprints = new Set();
    const matchedRequestIds = new Set();

    function match(entry, requests) {
      const entryFingerprint = fingerprint(entry);
      if (processedFingerprints.has(entryFingerprint)) return null;

      const method = entry.request?.method;
      const url = entry.request?.url;
      if (!method || !url) return null;

      const harTimestamp = Date.parse(entry.startedDateTime || '');
      const harBody = harBodyText(entry);
      const candidates = [];

      for (const request of requests) {
        if (!request?.id || matchedRequestIds.has(request.id)) continue;
        if (request.method !== method || request.url !== url) continue;

        if (harBody !== null && request.requestBody &&
            stableHash(harBody) !== stableHash(request.requestBody)) {
          continue;
        }

        const requestTimestamp = Number(request.timestamp);
        const timeDifference = Number.isFinite(harTimestamp) && Number.isFinite(requestTimestamp)
          ? Math.abs(harTimestamp - requestTimestamp)
          : 0;
        if (timeDifference > maxTimeDifferenceMs) continue;
        candidates.push({ request, timeDifference });
      }

      candidates.sort((first, second) => first.timeDifference - second.timeDifference);
      const matched = candidates[0]?.request || null;
      if (!matched) return null;

      processedFingerprints.add(entryFingerprint);
      matchedRequestIds.add(matched.id);
      return matched;
    }

    return {
      fingerprint,
      isProcessed: entry => processedFingerprints.has(fingerprint(entry)),
      match
    };
  }

  return {
    createMatcher,
    fingerprint,
    harBodyText,
    stableHash
  };
});
