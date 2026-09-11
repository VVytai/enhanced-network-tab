(function initializeHttpModelCore(root, factory) {
  const core = factory();

  root.EnhancedNetworkTab = root.EnhancedNetworkTab || {};
  root.EnhancedNetworkTab.HttpModelCore = core;

  if (typeof module === 'object' && module.exports) {
    module.exports = core;
  }
})(typeof globalThis !== 'undefined' ? globalThis : this, function createHttpModelCore() {
  'use strict';

  function normalizeHeaders(headers) {
    if (Array.isArray(headers)) {
      return headers
        .filter(header => header && header.name !== undefined)
        .map(header => ({
          name: String(header.name),
          value: String(header.value ?? '')
        }));
    }

    if (headers && typeof headers === 'object') {
      return Object.entries(headers).map(([name, value]) => ({
        name,
        value: String(value ?? '')
      }));
    }

    return [];
  }

  function cloneHeaders(headers) {
    return normalizeHeaders(headers);
  }

  function parseHeaders(text) {
    const headers = [];

    for (const line of String(text || '').split(/\r?\n/)) {
      if (!line.trim()) continue;
      const separator = line.indexOf(':');
      if (separator <= 0) continue;

      headers.push({
        name: line.slice(0, separator).trim(),
        value: line.slice(separator + 1).trim()
      });
    }

    return headers;
  }

  function formatHeaders(headers) {
    return normalizeHeaders(headers)
      .map(header => `${header.name}: ${header.value}`)
      .join('\n');
  }

  function getHeaderValue(headers, name) {
    const normalizedName = String(name).toLowerCase();
    return normalizeHeaders(headers)
      .find(header => header.name.toLowerCase() === normalizedName)?.value;
  }

  function removeHeader(headers, name) {
    const normalizedName = String(name).toLowerCase();
    return normalizeHeaders(headers)
      .filter(header => header.name.toLowerCase() !== normalizedName);
  }

  function replaceHeadersFromSource(headers, sourceHeaders, names) {
    const normalizedNames = new Set(
      Array.from(names || [], name => String(name).toLowerCase())
    );
    const retainedHeaders = normalizeHeaders(headers).filter(
      header => !normalizedNames.has(header.name.toLowerCase())
    );
    const sourceReplacements = normalizeHeaders(sourceHeaders).filter(
      header => normalizedNames.has(header.name.toLowerCase())
    );

    return [...retainedHeaders, ...sourceReplacements];
  }

  function headersEqual(first, second) {
    const a = normalizeHeaders(first);
    const b = normalizeHeaders(second);
    if (a.length !== b.length) return false;

    return a.every((header, index) =>
      header.name === b[index].name && header.value === b[index].value
    );
  }

  function headersByteLength(headers) {
    return normalizeHeaders(headers).reduce((total, header) =>
      total + new TextEncoder().encode(`${header.name}: ${header.value}\r\n`).byteLength,
    0);
  }

  function combineRawRequestBytes(rawParts) {
    if (!Array.isArray(rawParts)) return null;
    if (rawParts.some(part => !part || part.bytes === undefined)) return null;

    const chunks = rawParts.map(part => new Uint8Array(part.bytes));
    const totalLength = chunks.reduce((total, chunk) => total + chunk.byteLength, 0);
    const combined = new Uint8Array(totalLength);
    let offset = 0;

    for (const chunk of chunks) {
      combined.set(chunk, offset);
      offset += chunk.byteLength;
    }

    return combined;
  }

  function bytesToBase64(bytes) {
    const data = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes || 0);
    let binary = '';
    const chunkSize = 8192;

    for (let offset = 0; offset < data.byteLength; offset += chunkSize) {
      binary += String.fromCharCode(...data.subarray(offset, offset + chunkSize));
    }

    return btoa(binary);
  }

  function base64ToBytes(base64) {
    const binary = atob(String(base64 || '').replace(/\s+/g, ''));
    const bytes = new Uint8Array(binary.length);
    for (let index = 0; index < binary.length; index += 1) {
      bytes[index] = binary.charCodeAt(index);
    }
    return bytes;
  }

  function tryDecodeUtf8(bytes) {
    try {
      return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    } catch (_) {
      return null;
    }
  }

  function encodeFormData(formData) {
    const parameters = new URLSearchParams();

    for (const [name, values] of Object.entries(formData || {})) {
      for (const value of Array.isArray(values) ? values : [values]) {
        parameters.append(name, String(value ?? ''));
      }
    }

    return parameters.toString();
  }

  function createRequestBodyModel(requestBody, maxBytes = Number.POSITIVE_INFINITY) {
    if (!requestBody) {
      return { kind: 'empty', text: '', byteLength: 0, editable: true, replayable: true };
    }

    if (Array.isArray(requestBody.raw)) {
      const rawByteLength = requestBody.raw.reduce((total, part) =>
        total + (part?.bytes?.byteLength || 0),
      0);
      if (rawByteLength > maxBytes) {
        return {
          kind: 'unavailable',
          text: '',
          byteLength: rawByteLength,
          editable: false,
          replayable: false,
          truncated: true,
          reason: `Request body exceeds the ${maxBytes}-byte capture limit.`
        };
      }

      const bytes = combineRawRequestBytes(requestBody.raw);
      if (!bytes) {
        return {
          kind: 'unavailable',
          text: '',
          byteLength: null,
          editable: false,
          replayable: false,
          reason: 'Request body contains a file or inaccessible raw data.'
        };
      }

      if (bytes.byteLength === 0) {
        return { kind: 'empty', text: '', byteLength: 0, editable: true, replayable: true };
      }

      const base64 = bytesToBase64(bytes);
      const utf8Text = tryDecodeUtf8(bytes);
      const needsContentTypeRefinement = Boolean(requestBody.formData);
      return {
        kind: utf8Text === null ? 'base64' : 'text',
        text: utf8Text === null ? base64 : utf8Text,
        utf8Text,
        base64,
        byteLength: bytes.byteLength,
        editable: !needsContentTypeRefinement,
        replayable: true,
        needsContentTypeRefinement,
        reason: needsContentTypeRefinement
          ? 'Body editing is available after headers determine the form encoding.'
          : undefined
      };
    }

    if (requestBody.formData) {
      const text = encodeFormData(requestBody.formData);
      return {
        kind: 'form',
        text,
        byteLength: new TextEncoder().encode(text).byteLength,
        editable: true,
        replayable: true
      };
    }

    return {
      kind: 'unavailable',
      text: '',
      byteLength: null,
      editable: false,
      replayable: false,
      reason: requestBody.error || 'Request body bytes are unavailable.'
    };
  }

  function refineRequestBodyModel(bodyModel, headers) {
    const model = { ...bodyModel };
    const contentType = (getHeaderValue(headers, 'content-type') || '').toLowerCase();

    if (contentType.includes('multipart/form-data')) {
      model.kind = model.base64 ? 'base64' : 'unavailable';
      model.text = model.base64 || '';
      model.editable = false;
      model.reason = 'Multipart bodies are shown as Base64 and cannot be edited safely.';
      return model;
    }

    if (contentType.includes('application/x-www-form-urlencoded') && model.utf8Text !== null) {
      model.kind = 'form';
      model.text = model.utf8Text ?? model.text;
      model.editable = true;
      model.reason = undefined;
      return model;
    }

    const isTextual = contentType.startsWith('text/') ||
      contentType.includes('json') ||
      contentType.includes('xml') ||
      contentType.includes('javascript');
    const isBinary = contentType.startsWith('image/') ||
      contentType.startsWith('audio/') ||
      contentType.startsWith('video/') ||
      contentType.includes('octet-stream') ||
      contentType.includes('application/pdf');

    if (isTextual && model.utf8Text !== null && model.utf8Text !== undefined) {
      model.kind = 'text';
      model.text = model.utf8Text;
      model.editable = true;
      model.reason = undefined;
    } else if (isBinary && model.base64) {
      model.kind = 'base64';
      model.text = model.base64;
      model.editable = true;
      model.reason = undefined;
    }

    return model;
  }

  function bodyEditorEncoding(bodyModel) {
    return bodyModel?.kind === 'base64' ? 'base64' : 'text';
  }

  function requestMethodAllowsBody(method) {
    const normalizedMethod = String(method || 'GET').toUpperCase();
    return normalizedMethod !== 'GET' && normalizedMethod !== 'HEAD';
  }

  function responseBodyEncodingForContentType(contentType) {
    const normalized = String(contentType || '').toLowerCase();
    const isTextual = normalized.startsWith('text/') ||
      normalized.includes('json') ||
      normalized.includes('xml') ||
      normalized.includes('javascript') ||
      normalized.includes('html') ||
      normalized.includes('x-www-form-urlencoded');
    return isTextual ? 'text' : 'base64';
  }

  return {
    base64ToBytes,
    bodyEditorEncoding,
    bytesToBase64,
    cloneHeaders,
    combineRawRequestBytes,
    createRequestBodyModel,
    encodeFormData,
    formatHeaders,
    getHeaderValue,
    headersByteLength,
    headersEqual,
    normalizeHeaders,
    parseHeaders,
    refineRequestBodyModel,
    removeHeader,
    replaceHeadersFromSource,
    requestMethodAllowsBody,
    responseBodyEncodingForContentType,
    tryDecodeUtf8
  };
});
