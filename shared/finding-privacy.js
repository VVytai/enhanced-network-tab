(function initializeFindingPrivacyCore(root, factory) {
  const core = factory();

  root.EnhancedNetworkTab = root.EnhancedNetworkTab || {};
  root.EnhancedNetworkTab.FindingPrivacyCore = core;

  if (typeof module === 'object' && module.exports) {
    module.exports = core;
  }
})(typeof globalThis !== 'undefined' ? globalThis : this, function createFindingPrivacyCore() {
  'use strict';

  function maskValue(value) {
    const text = String(value ?? '');
    if (text.length <= 8) return '*'.repeat(text.length);
    return `${text.slice(0, 4)}${'*'.repeat(Math.min(24, text.length - 8))}${text.slice(-4)}`;
  }

  function isSensitiveFinding(finding, category) {
    return ['apiKeys', 'credentials', 'secrets'].includes(category) ||
      ['critical', 'high'].includes(finding?.severity);
  }

  function sanitizeItem(item, category) {
    if (!isSensitiveFinding(item, category)) return { ...item };
    return {
      ...item,
      match: maskValue(item.match),
      extractedValue: item.extractedValue === undefined
        ? undefined
        : maskValue(item.extractedValue),
      context: item.context === undefined ? undefined : '[sensitive context hidden]',
      maskedAtRest: true
    };
  }

  function sanitizeSecurityFinding(finding) {
    const categoryNames = [
      'apiKeys',
      'credentials',
      'emails',
      'apiEndpoints',
      'parameters',
      'paths'
    ];
    const sanitized = { ...finding, maskedAtRest: true };
    const categories = {};

    for (const category of categoryNames) {
      const items = (finding?.categories?.[category] || finding?.[category] || [])
        .map(item => sanitizeItem(item, category));
      categories[category] = items;
      sanitized[category] = items;
    }
    sanitized.categories = categories;
    return sanitized;
  }

  return {
    maskValue,
    sanitizeSecurityFinding
  };
});
