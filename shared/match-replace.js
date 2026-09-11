(function initializeMatchReplaceCore(root, factory) {
  const core = factory();

  root.EnhancedNetworkTab = root.EnhancedNetworkTab || {};
  root.EnhancedNetworkTab.MatchReplaceCore = core;

  if (typeof module === 'object' && module.exports) {
    module.exports = core;
  }
})(typeof globalThis !== 'undefined' ? globalThis : this, function createMatchReplaceCore() {
  'use strict';

  const HTTP_HEADER_NAME = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;

  function normalizeHeaderName(value) {
    return String(value ?? '').trim();
  }

  function isValidHeaderName(value) {
    return HTTP_HEADER_NAME.test(normalizeHeaderName(value));
  }

  function parseHeaderLine(value) {
    const line = String(value ?? '');
    const separator = line.indexOf(':');
    if (separator <= 0) return null;

    const name = line.slice(0, separator).trim();
    if (!isValidHeaderName(name)) return null;

    return {
      name,
      value: line.slice(separator + 1).replace(/^\s*/, '')
    };
  }

  function migrateLegacyHeaderRule(rule) {
    if (rule?.target !== 'headers' || normalizeHeaderName(rule.headerName)) {
      return { ...rule };
    }

    // Earlier versions only transformed header values, even though the UI
    // allowed users to enter a complete "Name: value" line. Migrate the
    // unambiguous case where both sides name the same header.
    const matchHeader = parseHeaderLine(rule.matchPattern);
    const replacementHeader = parseHeaderLine(rule.replaceValue);
    if (!matchHeader || !replacementHeader ||
        matchHeader.name.toLowerCase() !== replacementHeader.name.toLowerCase()) {
      return { ...rule, headerName: '' };
    }

    return {
      ...rule,
      headerName: matchHeader.name,
      matchPattern: matchHeader.value,
      replaceValue: replacementHeader.value
    };
  }

  function sanitizeRules(rules) {
    if (!Array.isArray(rules)) return [];

    return rules.map(originalRule => {
      const rule = migrateLegacyHeaderRule(originalRule || {});
      if (rule.target === 'headers') {
        rule.headerName = normalizeHeaderName(rule.headerName);
      }
      if (rule.target === 'body') {
        rule.enabled = false;
        rule.disabledReason = 'request-body-unsupported';
      }
      return rule;
    });
  }

  function applyRuleReplacement(source, rule) {
    const input = String(source ?? '');

    try {
      const type = rule.matchType || 'regex';
      const pattern = rule.matchPattern;
      const replacement = String(rule.replaceValue ?? '');

      if (!pattern) return input;

      switch (type) {
        case 'regex':
          return input.replace(new RegExp(pattern, 'g'), replacement);
        case 'contains':
          return input.split(pattern).join(replacement);
        case 'starts_with':
          return input.startsWith(pattern)
            ? replacement + input.substring(pattern.length)
            : input;
        case 'ends_with':
          return input.endsWith(pattern)
            ? input.substring(0, input.length - pattern.length) + replacement
            : input;
        case 'exact':
          return input === pattern ? replacement : input;
        default:
          return input;
      }
    } catch (error) {
      console.error('Error applying rule replacement:', error);
      return input;
    }
  }

  function headerNameMatches(header, rule) {
    const selector = normalizeHeaderName(rule.headerName);
    return selector === '' ||
      String(header?.name ?? '').toLowerCase() === selector.toLowerCase();
  }

  function applyHeaderRules(originalHeaders, rules) {
    if (!Array.isArray(originalHeaders) || !Array.isArray(rules) || rules.length === 0) {
      return { headers: originalHeaders, modified: false };
    }

    let modified = false;
    const headers = originalHeaders.map(header => {
      let value = String(header?.value ?? '');

      for (const rule of rules) {
        if (!rule.enabled || rule.target !== 'headers' ||
            !headerNameMatches(header, rule)) {
          continue;
        }

        const replaced = applyRuleReplacement(value, rule);
        if (replaced !== value) {
          value = replaced;
          modified = true;
        }
      }

      return value === String(header?.value ?? '')
        ? header
        : { name: header.name, value };
    });

    return { headers, modified };
  }

  return {
    applyHeaderRules,
    applyRuleReplacement,
    headerNameMatches,
    isValidHeaderName,
    migrateLegacyHeaderRule,
    normalizeHeaderName,
    parseHeaderLine,
    sanitizeRules
  };
});
