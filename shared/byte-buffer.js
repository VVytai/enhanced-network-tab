(function initializeByteBufferCore(root, factory) {
  const core = factory();

  root.EnhancedNetworkTab = root.EnhancedNetworkTab || {};
  root.EnhancedNetworkTab.ByteBufferCore = core;

  if (typeof module === 'object' && module.exports) {
    module.exports = core;
  }
})(typeof globalThis !== 'undefined' ? globalThis : this, function createByteBufferCore() {
  'use strict';

  function copyBytes(data) {
    const source = data instanceof Uint8Array ? data : new Uint8Array(data);
    return source.slice();
  }

  function combineChunks(chunks, byteLength) {
    const combined = new Uint8Array(byteLength);
    let offset = 0;
    for (const chunk of chunks) {
      combined.set(chunk, offset);
      offset += chunk.byteLength;
    }
    return combined;
  }

  function createBoundedCollector(limit) {
    const chunks = [];
    let capturedBytes = 0;
    let totalBytes = 0;

    function add(data) {
      const bytes = data instanceof Uint8Array ? data : new Uint8Array(data);
      totalBytes += bytes.byteLength;
      const remaining = Math.max(0, limit - capturedBytes);
      const capturedNow = Math.min(remaining, bytes.byteLength);
      if (capturedNow > 0) {
        chunks.push(bytes.subarray(0, capturedNow).slice());
        capturedBytes += capturedNow;
      }
      return capturedNow;
    }

    return {
      add,
      toUint8Array: () => combineChunks(chunks, capturedBytes),
      get capturedBytes() { return capturedBytes; },
      get totalBytes() { return totalBytes; },
      get truncated() { return totalBytes > capturedBytes; }
    };
  }

  function createWholeChunkBuffer(limit) {
    const chunks = [];
    let byteLength = 0;

    function tryAdd(data) {
      const bytes = data instanceof Uint8Array ? data : new Uint8Array(data);
      if (byteLength + bytes.byteLength > limit) return false;
      const copy = copyBytes(bytes);
      chunks.push(copy);
      byteLength += copy.byteLength;
      return true;
    }

    function drain() {
      const combined = combineChunks(chunks, byteLength);
      chunks.length = 0;
      byteLength = 0;
      return combined;
    }

    return {
      drain,
      tryAdd,
      get byteLength() { return byteLength; }
    };
  }

  return {
    combineChunks,
    createBoundedCollector,
    createWholeChunkBuffer
  };
});
