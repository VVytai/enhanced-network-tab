let captureEnabled = false;
let interceptEnabled = false;
let interceptSettings = {
  methods: ['POST', 'PUT', 'PATCH', 'DELETE'], // Default methods to intercept
  includeGET: false,
  urlPatterns: [], // URL patterns to intercept (regex strings)
  excludePatterns: [], // URL patterns to exclude from interception
  excludeExtensions: ['css', 'js', 'png', 'jpg', 'jpeg', 'gif', 'ico', 'svg', 'woff', 'woff2', 'ttf', 'eot'], // File extensions to exclude
  interceptResponses: false // Whether to also intercept responses for modification
};
let requests = new Map();
let activeTabId = null;
let devtoolsPorts = new Map();
let pendingRequests = new Map();
let pendingResponses = new Map(); // For response interception
let requestIdCounter = 0;
let requestIdMap = new Map();
let interceptedRequestIds = new Set(); // Track which requests should have their responses intercepted

const MAX_REQUESTS = 100;

browser.tabs.onActivated.addListener((activeInfo) => {
  activeTabId = activeInfo.tabId;
  updateIcon();
});

browser.tabs.query({ active: true, currentWindow: true }).then((tabs) => {
  if (tabs[0]) {
    activeTabId = tabs[0].id;
  }
});

browser.browserAction.onClicked.addListener(() => {
  captureEnabled = !captureEnabled;
  updateIcon();
  notifyDevTools({ type: 'captureStateChanged', enabled: captureEnabled });
});

function updateIcon() {
  const iconPath = captureEnabled ? {
    16: 'icons/icon-active-16.png',
    32: 'icons/icon-active-32.png',
    48: 'icons/icon-active-48.png',
    128: 'icons/icon-active-128.png'
  } : {
    16: 'icons/icon-16.png',
    32: 'icons/icon-32.png',
    48: 'icons/icon-48.png',
    128: 'icons/icon-128.png'
  };
  
  browser.browserAction.setIcon({ path: iconPath });
  browser.browserAction.setTitle({ 
    title: `Security Proxy - ${captureEnabled ? 'Capturing' : 'Idle'}${interceptEnabled ? ' (Intercepting)' : ''}`
  });
}

function getRequestBody(details) {
  if (details.requestBody) {
    if (details.requestBody.formData) {
      return JSON.stringify(details.requestBody.formData);
    } else if (details.requestBody.raw) {
      const decoder = new TextDecoder('utf-8');
      return details.requestBody.raw.map(data => decoder.decode(new Uint8Array(data.bytes))).join('');
    }
  }
  return '';
}

function shouldInterceptRequest(details) {
  // Check if method should be intercepted
  let shouldIntercept = false;
  
  if (interceptSettings.includeGET && details.method === 'GET') {
    shouldIntercept = true;
  } else if (interceptSettings.methods.includes(details.method)) {
    shouldIntercept = true;
  }
  
  if (!shouldIntercept) {
    return false;
  }
  
  // Check file extensions to exclude
  if (interceptSettings.excludeExtensions.length > 0) {
    const url = new URL(details.url);
    const pathname = url.pathname.toLowerCase();
    const hasExcludedExtension = interceptSettings.excludeExtensions.some(ext => {
      return pathname.endsWith('.' + ext.toLowerCase()) || 
             pathname.includes('.' + ext.toLowerCase() + '?') ||
             pathname.includes('.' + ext.toLowerCase() + '#');
    });
    
    if (hasExcludedExtension) {
      return false;
    }
  }
  
  // Check URL patterns to include
  if (interceptSettings.urlPatterns.length > 0) {
    const matchesIncludePattern = interceptSettings.urlPatterns.some(pattern => {
      try {
        const regex = new RegExp(pattern, 'i');
        return regex.test(details.url);
      } catch (e) {
        console.warn('Invalid regex pattern:', pattern);
        return false;
      }
    });
    
    if (!matchesIncludePattern) {
      return false;
    }
  }
  
  // Check URL patterns to exclude
  if (interceptSettings.excludePatterns.length > 0) {
    const matchesExcludePattern = interceptSettings.excludePatterns.some(pattern => {
      try {
        const regex = new RegExp(pattern, 'i');
        return regex.test(details.url);
      } catch (e) {
        console.warn('Invalid regex pattern:', pattern);
        return false;
      }
    });
    
    if (matchesExcludePattern) {
      return false;
    }
  }
  
  return true;
}

browser.webRequest.onBeforeRequest.addListener(
  (details) => {
    // Check if we should process this request
    if (!captureEnabled || details.tabId !== activeTabId || details.tabId === -1) {
      return {};
    }
    
    const requestId = `${details.requestId}_${requestIdCounter++}`;
    requestIdMap.set(details.requestId, requestId);
    
    const requestData = {
      id: requestId,
      originalRequestId: details.requestId,
      timestamp: Date.now(),
      url: details.url,
      method: details.method,
      type: details.type,
      requestHeaders: {},
      requestBody: getRequestBody(details),
      requestSize: 0,
      responseHeaders: {},
      responseBody: '',
      responseSize: 0,
      statusCode: null,
      statusLine: '',
      tabId: details.tabId,
      completed: false,
      intercepted: false,
      shouldIntercept: false
    };
    
    // Check if this request should be intercepted (but don't intercept yet)
    if (interceptEnabled && shouldInterceptRequest(details)) {
      requestData.shouldIntercept = true;
      requestData.intercepted = true;
      requestData.statusLine = 'Intercepted';
      
      // Mark this request for potential response interception
      if (interceptSettings.interceptResponses) {
        interceptedRequestIds.add(details.requestId);
      }
    }
    
    // Store in requests since capture is enabled
    requests.set(requestId, requestData);
    
    if (requests.size > MAX_REQUESTS) {
      const oldestKey = requests.keys().next().value;
      const oldRequest = requests.get(oldestKey);
      if (oldRequest) {
        requestIdMap.delete(oldRequest.originalRequestId);
      }
      requests.delete(oldestKey);
    }
    
    notifyDevTools({
      type: 'newRequest',
      request: requestData
    });
    
    return {};
  },
  { urls: ["<all_urls>"] },
  ["requestBody"]
);

browser.webRequest.onBeforeSendHeaders.addListener(
  (details) => {
    if (!captureEnabled || details.tabId !== activeTabId) return {};
    
    const requestId = requestIdMap.get(details.requestId);
    if (!requestId) return {};
    
    const request = requests.get(requestId);
    if (request) {
      request.requestHeaders = details.requestHeaders.reduce((acc, header) => {
        acc[header.name] = header.value;
        if (header.name.toLowerCase() === 'content-length') {
          request.requestSize = parseInt(header.value, 10) || 0;
        }
        return acc;
      }, {});
      
      notifyDevTools({
        type: 'updateRequest',
        request: request
      });
      
      // NOW intercept if needed (after we have headers)
      if (request.shouldIntercept && !pendingRequests.has(details.requestId)) {
        return new Promise((resolve) => {
          const pendingData = {
            ...request,
            resolve: resolve,
            originalRequestId: details.requestId
          };
          pendingRequests.set(details.requestId, pendingData);
          
          notifyDevTools({
            type: 'interceptRequest',
            request: request
          });
        });
      }
    }
    
    return {};
  },
  { urls: ["<all_urls>"] },
  ["blocking", "requestHeaders"]
);

browser.webRequest.onHeadersReceived.addListener(
  (details) => {
    if (!captureEnabled || details.tabId !== activeTabId || details.tabId === -1) {
      return {};
    }
    
    const requestId = requestIdMap.get(details.requestId);
    if (!requestId) return {};
    
    const request = requests.get(requestId);
    if (!request) return {};
    
    // Check if this response should be intercepted
    const shouldInterceptResponse = interceptedRequestIds.has(details.requestId);
    
    const contentType = details.responseHeaders?.find(h => 
      h.name.toLowerCase() === 'content-type'
    )?.value || '';
    
    const isTextContent = contentType.includes('json') || 
        contentType.includes('text') || 
        contentType.includes('xml') ||
        contentType.includes('javascript') ||
        contentType.includes('html');
    
    const isImageContent = contentType.includes('image/');
    
    if (isTextContent || isImageContent) {
      
      const filter = browser.webRequest.filterResponseData(details.requestId);
      const decoder = new TextDecoder('utf-8');
      let responseData = [];
      
      if (shouldInterceptResponse) {
        // Response interception mode
        filter.ondata = event => {
          responseData.push(event.data);
          // Don't write data yet, wait for user input
        };
        
        filter.onstop = event => {
          try {
            const combinedData = new Uint8Array(
              responseData.reduce((acc, chunk) => acc + chunk.byteLength, 0)
            );
            let offset = 0;
            for (const chunk of responseData) {
              combinedData.set(new Uint8Array(chunk), offset);
              offset += chunk.byteLength;
            }
            
            let bodyContent;
            if (isImageContent) {
              // Convert binary image data to base64
              let binary = '';
              const len = combinedData.byteLength;
              for (let i = 0; i < len; i++) {
                binary += String.fromCharCode(combinedData[i]);
              }
              bodyContent = btoa(binary);
              request.responseBody = bodyContent;
              request.isBase64 = true;
            } else {
              bodyContent = decoder.decode(combinedData);
              request.responseBody = bodyContent.substring(0, 50000);
              request.isBase64 = false;
            }
            
            // Store response data for modification
            const responseInterceptData = {
              requestId: requestId,
              originalRequestId: details.requestId,
              filter: filter,
              responseHeaders: details.responseHeaders,
              responseBody: bodyContent,
              statusCode: details.statusCode,
              statusLine: details.statusLine,
              request: request,
              isBase64: isImageContent
            };
            
            pendingResponses.set(details.requestId, responseInterceptData);
            
            // Remove from intercepted requests tracking
            interceptedRequestIds.delete(details.requestId);
            
            // Notify DevTools about response interception
            notifyDevTools({
              type: 'interceptResponse',
              response: {
                requestId: requestId,
                statusCode: details.statusCode,
                statusLine: details.statusLine,
                responseHeaders: details.responseHeaders,
                responseBody: bodyContent,
                isBase64: isImageContent
              }
            });
            
          } catch (e) {
            console.error('Failed to decode response for interception:', e);
            filter.close();
          }
        };
      } else {
        // Normal mode - just capture for display
        filter.ondata = event => {
          responseData.push(event.data);
          filter.write(event.data);
        };
        
        filter.onstop = event => {
          filter.close();
          
          try {
            const combinedData = new Uint8Array(
              responseData.reduce((acc, chunk) => acc + chunk.byteLength, 0)
            );
            let offset = 0;
            for (const chunk of responseData) {
              combinedData.set(new Uint8Array(chunk), offset);
              offset += chunk.byteLength;
            }
            
            if (isImageContent) {
              // Convert binary image data to base64
              let binary = '';
              const len = combinedData.byteLength;
              for (let i = 0; i < len; i++) {
                binary += String.fromCharCode(combinedData[i]);
              }
              const base64 = btoa(binary);
              request.responseBody = base64;
              request.isBase64 = true;
            } else {
              // Text content
              const text = decoder.decode(combinedData);
              request.responseBody = text.substring(0, 50000);
              request.isBase64 = false;
            }
            
            notifyDevTools({
              type: 'updateRequest',
              request: request
            });
          } catch (e) {
            console.error('Failed to decode response:', e);
          }
        };
      }
    }
    
    return {};
  },
  { urls: ["<all_urls>"], types: ["xmlhttprequest", "main_frame", "sub_frame", "image", "media", "font", "script", "stylesheet", "other"] },
  ["blocking", "responseHeaders"]
);

browser.webRequest.onResponseStarted.addListener(
  (details) => {
    if (!captureEnabled || details.tabId !== activeTabId) return;
    
    const requestId = requestIdMap.get(details.requestId);
    if (!requestId) return;
    
    const request = requests.get(requestId);
    if (request) {
      request.statusCode = details.statusCode;
      request.statusLine = details.statusLine;
      request.responseHeaders = details.responseHeaders.reduce((acc, header) => {
        acc[header.name] = header.value;
        if (header.name.toLowerCase() === 'content-length') {
          request.responseSize = parseInt(header.value, 10) || 0;
        }
        return acc;
      }, {});
      notifyDevTools({
        type: 'updateRequest',
        request: request
      });
    }
  },
  { urls: ["<all_urls>"] },
  ["responseHeaders"]
);

browser.webRequest.onCompleted.addListener(
  (details) => {
    if (!captureEnabled || details.tabId !== activeTabId) return;
    
    const requestId = requestIdMap.get(details.requestId);
    if (!requestId) return;
    
    const request = requests.get(requestId);
    if (request) {
      request.completed = true;
      notifyDevTools({
        type: 'updateRequest',
        request: request
      });
      requestIdMap.delete(details.requestId);
    }
  },
  { urls: ["<all_urls>"] }
);

browser.webRequest.onErrorOccurred.addListener(
  (details) => {
    if (!captureEnabled || details.tabId !== activeTabId) return;
    
    const requestId = requestIdMap.get(details.requestId);
    if (!requestId) return;
    
    const request = requests.get(requestId);
    if (request) {
      request.statusCode = 0;
      request.statusLine = `Error: ${details.error}`;
      request.completed = true;
      notifyDevTools({
        type: 'updateRequest',
        request: request
      });
      requestIdMap.delete(details.requestId);
    }
  },
  { urls: ["<all_urls>"] }
);

browser.runtime.onConnect.addListener((port) => {
  if (port.name === 'devtools-panel') {
    const tabId = port.sender?.tab?.id || 'devtools';
    devtoolsPorts.set(tabId, port);
    
    port.postMessage({
      type: 'initialState',
      captureEnabled: captureEnabled,
      interceptEnabled: interceptEnabled,
      interceptSettings: interceptSettings,
      requests: Array.from(requests.values())
    });
    
    port.onMessage.addListener((msg) => {
      handleDevToolsMessage(msg, port);
    });
    
    port.onDisconnect.addListener(() => {
      devtoolsPorts.delete(tabId);
    });
  }
});

function handleDevToolsMessage(msg, port) {
  switch (msg.type) {
    case 'toggleCapture':
      captureEnabled = msg.enabled;
      // If capture is disabled, also disable intercept
      if (!captureEnabled && interceptEnabled) {
        interceptEnabled = false;
        notifyDevTools({ type: 'interceptStateChanged', enabled: false });
      }
      updateIcon();
      notifyDevTools({ type: 'captureStateChanged', enabled: captureEnabled });
      break;
      
    case 'toggleIntercept':
      interceptEnabled = msg.enabled;
      // If intercept is enabled, also enable capture
      if (interceptEnabled && !captureEnabled) {
        captureEnabled = true;
        notifyDevTools({ type: 'captureStateChanged', enabled: true });
      }
      updateIcon();
      notifyDevTools({ type: 'interceptStateChanged', enabled: interceptEnabled });
      break;
      
    case 'clearRequests':
      requests.clear();
      notifyDevTools({ type: 'requestsCleared' });
      break;
      
    case 'forwardRequest':
      handleForwardRequest(msg.requestId, msg.modifiedRequest);
      break;
      
    case 'dropRequest':
      handleDropRequest(msg.requestId);
      break;
      
    case 'getRequestBody':
      const request = requests.get(msg.requestId);
      if (request) {
        fetchResponseBody(request);
      }
      break;
      
    case 'sendRepeaterRequest':
      handleRepeaterRequest(msg.requestData, port);
      break;
      
    case 'updateInterceptSettings':
      interceptSettings = { ...interceptSettings, ...msg.settings };
      notifyDevTools({ type: 'interceptSettingsChanged', settings: interceptSettings });
      break;
      
    case 'getInterceptSettings':
      port.postMessage({ type: 'interceptSettingsResponse', settings: interceptSettings });
      break;
      
    case 'forwardResponse':
      handleForwardResponse(msg.requestId, msg.modifiedResponse);
      break;
      
    case 'dropResponse':
      handleDropResponse(msg.requestId);
      break;
      
    case 'disableIntercept':
      handleDisableIntercept(msg.currentRequestId, msg.currentType);
      break;
  }
}

async function handleForwardRequest(requestId, modifiedRequest) {
  // Find the pending request by the custom request ID
  let originalRequestId = null;
  let pending = null;
  
  for (const [key, value] of pendingRequests.entries()) {
    if (value.id === requestId) {
      originalRequestId = key;
      pending = value;
      break;
    }
  }
  
  if (pending && pending.resolve) {
    const request = requests.get(requestId);
    
    // Detect if the request was modified
    const wasModified = modifiedRequest && (
      modifiedRequest.url !== pending.url ||
      modifiedRequest.method !== pending.method ||
      JSON.stringify(modifiedRequest.headers) !== JSON.stringify(pending.requestHeaders) ||
      modifiedRequest.body !== pending.requestBody
    );
    
    if (wasModified && request) {
      // Cancel the original request
      pending.resolve({ cancel: true });
      pendingRequests.delete(originalRequestId);
      
      // Store original request data for comparison
      request.originalUrl = pending.url;
      request.originalMethod = pending.method;
      request.originalHeaders = { ...pending.requestHeaders };
      request.originalBody = pending.requestBody;
      
      // Store modified request data
      request.modifiedUrl = modifiedRequest.url;
      request.modifiedMethod = modifiedRequest.method;
      request.modifiedHeaders = { ...modifiedRequest.headers };
      request.modifiedBody = modifiedRequest.body;
      
      // Update status to show we're resending
      request.intercepted = false;
      request.statusLine = 'Resending (Modified)';
      request.wasModified = true;
      notifyDevTools({
        type: 'updateRequest',
        request: request
      });
      
      // Send the modified request as a new fetch request
      try {
        const fetchOptions = {
          method: modifiedRequest.method,
          headers: modifiedRequest.headers
        };
        
        // Add body for methods that support it
        if (['POST', 'PUT', 'PATCH'].includes(modifiedRequest.method) && modifiedRequest.body) {
          fetchOptions.body = modifiedRequest.body;
        }
        
        const startTime = Date.now();
        const response = await fetch(modifiedRequest.url, fetchOptions);
        const duration = Date.now() - startTime;
        
        // Capture response headers
        const responseHeaders = {};
        response.headers.forEach((value, key) => {
          responseHeaders[key] = value;
        });
        
        // Capture response body
        const contentType = response.headers.get('content-type') || '';
        let responseBody = '';
        
        if (contentType.includes('image/')) {
          // Handle image responses
          const blob = await response.blob();
          const arrayBuffer = await blob.arrayBuffer();
          const uint8Array = new Uint8Array(arrayBuffer);
          let binary = '';
          for (let i = 0; i < uint8Array.byteLength; i++) {
            binary += String.fromCharCode(uint8Array[i]);
          }
          responseBody = btoa(binary);
          request.isBase64 = true;
        } else {
          // Handle text responses
          responseBody = await response.text();
          responseBody = responseBody.substring(0, 50000); // Limit size
          request.isBase64 = false;
        }
        
        // Update request with response data
        request.statusCode = response.status;
        request.statusLine = `Modified & Resent (${duration}ms)`;
        request.responseHeaders = responseHeaders;
        request.responseBody = responseBody;
        request.completed = true;
        
        notifyDevTools({
          type: 'updateRequest',
          request: request
        });
        
      } catch (error) {
        // Handle fetch errors
        request.statusCode = 0;
        request.statusLine = `Modification Failed: ${error.message}`;
        request.completed = true;
        
        notifyDevTools({
          type: 'updateRequest',
          request: request
        });
      }
    } else {
      // Request was not modified, just forward it as-is
      pending.resolve({});
      pendingRequests.delete(originalRequestId);
      
      if (request) {
        request.intercepted = false;
        request.statusLine = 'Forwarded (Unmodified)';
        notifyDevTools({
          type: 'updateRequest',
          request: request
        });
      }
    }
  }
}

function handleDropRequest(requestId) {
  // Find the pending request by the custom request ID
  let originalRequestId = null;
  let pending = null;
  
  for (const [key, value] of pendingRequests.entries()) {
    if (value.id === requestId) {
      originalRequestId = key;
      pending = value;
      break;
    }
  }
  
  if (pending && pending.resolve) {
    // Update request status to show it was dropped
    const request = requests.get(requestId);
    if (request) {
      request.intercepted = false;
      request.statusLine = 'Dropped';
      request.statusCode = 0;
      request.completed = true;
      notifyDevTools({
        type: 'updateRequest',
        request: request
      });
    }
    
    pending.resolve({ cancel: true });
    pendingRequests.delete(originalRequestId);
  }
}

async function fetchResponseBody(request) {
  try {
    const response = await fetch(request.url, {
      method: 'GET',
      credentials: 'omit'
    });
    const text = await response.text();
    request.responseBody = text.substring(0, 50000);
    notifyDevTools({
      type: 'updateRequest',
      request: request
    });
  } catch (error) {
    console.error('Failed to fetch response body:', error);
  }
}

function handleForwardResponse(requestId, modifiedResponse) {
  // Find the pending response by the custom request ID
  let originalRequestId = null;
  let pending = null;
  
  for (const [key, value] of pendingResponses.entries()) {
    if (value.requestId === requestId) {
      originalRequestId = key;
      pending = value;
      break;
    }
  }
  
  if (pending && pending.filter) {
    try {
      // Update request status
      const request = requests.get(requestId);
      if (request) {
        request.responseIntercepted = false;
        request.statusLine = 'Response Modified';
        notifyDevTools({
          type: 'updateRequest',
          request: request
        });
      }
      
      // Write modified response
      const modifiedData = new TextEncoder().encode(modifiedResponse.body || pending.responseBody);
      pending.filter.write(modifiedData);
      pending.filter.close();
      
      pendingResponses.delete(originalRequestId);
    } catch (e) {
      console.error('Failed to forward modified response:', e);
      pending.filter.close();
      pendingResponses.delete(originalRequestId);
    }
  }
}

function handleDropResponse(requestId) {
  // Find the pending response by the custom request ID
  let originalRequestId = null;
  let pending = null;
  
  for (const [key, value] of pendingResponses.entries()) {
    if (value.requestId === requestId) {
      originalRequestId = key;
      pending = value;
      break;
    }
  }
  
  if (pending && pending.filter) {
    // Update request status
    const request = requests.get(requestId);
    if (request) {
      request.responseIntercepted = false;
      request.statusLine = 'Response Dropped';
      request.statusCode = 0;
      notifyDevTools({
        type: 'updateRequest',
        request: request
      });
    }
    
    // Close filter without writing any data (effectively dropping the response)
    pending.filter.close();
    pendingResponses.delete(originalRequestId);
  }
}

function handleDisableIntercept(currentRequestId, currentType) {
  // Disable intercept globally
  interceptEnabled = false;
  
  // Forward current request/response first
  if (currentType === 'request') {
    // Find and forward current request
    let currentOriginalRequestId = null;
    let currentPending = null;
    
    for (const [key, value] of pendingRequests.entries()) {
      if (value.id === currentRequestId) {
        currentOriginalRequestId = key;
        currentPending = value;
        break;
      }
    }
    
    if (currentPending && currentPending.resolve) {
      currentPending.resolve({});
      pendingRequests.delete(currentOriginalRequestId);
    }
  } else if (currentType === 'response') {
    // Find and forward current response
    let currentOriginalRequestId = null;
    let currentPending = null;
    
    for (const [key, value] of pendingResponses.entries()) {
      if (value.requestId === currentRequestId) {
        currentOriginalRequestId = key;
        currentPending = value;
        break;
      }
    }
    
    if (currentPending && currentPending.filter) {
      const originalData = new TextEncoder().encode(currentPending.responseBody);
      currentPending.filter.write(originalData);
      currentPending.filter.close();
      pendingResponses.delete(currentOriginalRequestId);
    }
  }
  
  // Forward all remaining pending requests
  for (const [requestId, pendingData] of pendingRequests.entries()) {
    if (pendingData.resolve) {
      pendingData.resolve({});
    }
  }
  pendingRequests.clear();
  
  // Forward all remaining pending responses
  for (const [requestId, responseData] of pendingResponses.entries()) {
    if (responseData.filter) {
      const originalData = new TextEncoder().encode(responseData.responseBody);
      responseData.filter.write(originalData);
      responseData.filter.close();
    }
  }
  pendingResponses.clear();
  
  // Clear intercepted request IDs
  interceptedRequestIds.clear();
  
  // Update icon and notify DevTools
  updateIcon();
  notifyDevTools({ 
    type: 'interceptStateChanged', 
    enabled: false 
  });
}

function notifyDevTools(message) {
  devtoolsPorts.forEach(port => {
    try {
      port.postMessage(message);
    } catch (e) {
      console.error('Failed to send message to devtools:', e);
    }
  });
}

async function handleRepeaterRequest(requestData, port) {
  try {
    const options = {
      method: requestData.method,
      headers: requestData.headers
    };
    
    if (['POST', 'PUT', 'PATCH'].includes(requestData.method) && requestData.body) {
      options.body = requestData.body;
    }
    
    const startTime = Date.now();
    const response = await fetch(requestData.url, options);
    const duration = Date.now() - startTime;
    
    const responseHeaders = {};
    response.headers.forEach((value, key) => {
      responseHeaders[key] = value;
    });
    
    const responseBody = await response.text();
    
    port.postMessage({
      type: 'repeaterResponse',
      response: {
        status: response.status,
        statusText: response.statusText,
        headers: responseHeaders,
        body: responseBody,
        duration: duration
      }
    });
  } catch (error) {
    port.postMessage({
      type: 'repeaterError',
      error: error.message
    });
  }
}