(function initializeInterceptionLifecycleCore(root, factory) {
  const core = factory();

  root.EnhancedNetworkTab = root.EnhancedNetworkTab || {};
  root.EnhancedNetworkTab.InterceptionLifecycleCore = core;

  if (typeof module === 'object' && module.exports) {
    module.exports = core;
  }
})(typeof globalThis !== 'undefined' ? globalThis : this, function createInterceptionLifecycleCore() {
  'use strict';

  const BODY_BYPASS_REASONS = new Set([
    'disabled',
    'dropped',
    'filter-error',
    'timeout'
  ]);

  function armPendingTimeout(pendingData, timeoutMs, onTimeout, timers = globalThis) {
    pendingData.released = false;
    pendingData.clearTimeout = timers.clearTimeout.bind(timers);
    pendingData.timeoutId = timers.setTimeout(() => {
      if (!pendingData.released) onTimeout();
    }, timeoutMs);
    return pendingData.timeoutId;
  }

  function settlePendingData(pendingData, action) {
    if (!pendingData || pendingData.released) return false;

    pendingData.released = true;
    if (pendingData.timeoutId !== undefined && pendingData.timeoutId !== null) {
      pendingData.clearTimeout(pendingData.timeoutId);
      pendingData.timeoutId = null;
    }
    action();
    return true;
  }

  function markResponseBodyBypass(pendingData, reason) {
    if (!BODY_BYPASS_REASONS.has(reason)) return false;
    if (!pendingData?.responseControl) return false;

    pendingData.responseControl.bypassBody = true;
    return true;
  }

  return {
    armPendingTimeout,
    markResponseBodyBypass,
    settlePendingData
  };
});
