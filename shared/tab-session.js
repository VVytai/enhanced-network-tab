(function initializeTabSessionCore(root, factory) {
  const core = factory();

  root.EnhancedNetworkTab = root.EnhancedNetworkTab || {};
  root.EnhancedNetworkTab.TabSessionCore = core;

  if (typeof module === 'object' && module.exports) {
    module.exports = core;
  }
})(typeof globalThis !== 'undefined' ? globalThis : this, function createTabSessionCore() {
  'use strict';

  function isValidTabId(tabId) {
    return Number.isInteger(tabId) && tabId >= 0;
  }

  function createTabSessionStore() {
    const sessions = new Map();

    function get(tabId, create = false) {
      if (!isValidTabId(tabId)) return null;

      if (!sessions.has(tabId) && create) {
        sessions.set(tabId, {
          tabId,
          captureEnabled: false,
          interceptEnabled: false,
          createdAt: Date.now()
        });
      }

      return sessions.get(tabId) || null;
    }

    function setCapture(tabId, enabled) {
      const session = get(tabId, true);
      session.captureEnabled = Boolean(enabled);

      if (!session.captureEnabled) {
        session.interceptEnabled = false;
      }

      return { ...session };
    }

    function setIntercept(tabId, enabled) {
      const session = get(tabId, true);
      session.interceptEnabled = Boolean(enabled);

      if (session.interceptEnabled) {
        session.captureEnabled = true;
      }

      return { ...session };
    }

    function remove(tabId) {
      return sessions.delete(tabId);
    }

    return {
      get,
      remove,
      setCapture,
      setIntercept,
      values: () => Array.from(sessions.values(), session => ({ ...session }))
    };
  }

  function createPortRegistry() {
    const records = new Map();
    let counter = 0;

    function register(port) {
      const id = `devtools_${++counter}`;
      const record = { id, port, inspectedTabId: null };
      records.set(id, record);
      return record;
    }

    function attachTab(id, tabId) {
      const record = records.get(id);
      if (!record || !isValidTabId(tabId)) return null;
      record.inspectedTabId = tabId;
      return record;
    }

    function unregister(id) {
      const record = records.get(id) || null;
      records.delete(id);
      return record;
    }

    function hasTab(tabId) {
      for (const record of records.values()) {
        if (record.inspectedTabId === tabId) return true;
      }
      return false;
    }

    function postMessage(message, tabId = null) {
      const failures = [];

      for (const record of records.values()) {
        if (tabId !== null && record.inspectedTabId !== tabId) continue;
        if (record.inspectedTabId === null) continue;

        try {
          record.port.postMessage(message);
        } catch (error) {
          failures.push({ record, error });
        }
      }

      return failures;
    }

    return {
      attachTab,
      get: id => records.get(id) || null,
      hasTab,
      postMessage,
      register,
      unregister,
      values: () => Array.from(records.values())
    };
  }

  function selectRequestIdsForEviction(entries, tabId, limit, isProtected = () => false) {
    const matchingIds = entries
      .filter(([, request]) => request.tabId === tabId)
      .map(([requestId]) => requestId);
    let excess = Math.max(0, matchingIds.length - limit);
    const evictions = [];

    for (const requestId of matchingIds) {
      if (excess <= 0) break;
      if (isProtected(requestId)) continue;
      evictions.push(requestId);
      excess -= 1;
    }

    return evictions;
  }

  return {
    createPortRegistry,
    createTabSessionStore,
    isValidTabId,
    selectRequestIdsForEviction
  };
});
