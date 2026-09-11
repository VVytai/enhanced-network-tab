let interceptSettings = {
  methods: ["POST", "PUT", "PATCH", "DELETE"],
  includeGET: false,
  urlPatterns: [],
  excludePatterns: [],
  excludeExtensions: [
    "css",
    "js",
    "png",
    "jpg",
    "jpeg",
    "gif",
    "ico",
    "svg",
    "woff",
    "woff2",
    "ttf",
    "eot",
  ],
  interceptResponses: false,
  useEarlyInterception: false,
  modifiedRequestAction: "repeater-draft",
  scopeEnabled: false,
  scopePatterns: [],
  scopeExcludePatterns: [],
};
let matchReplaceRules = [];
let requests = new Map();
let activeTabId = null;
const tabSessions =
  globalThis.EnhancedNetworkTab.TabSessionCore.createTabSessionStore();
const devtoolsPorts =
  globalThis.EnhancedNetworkTab.TabSessionCore.createPortRegistry();
const HttpModel = globalThis.EnhancedNetworkTab.HttpModelCore;
const ByteBufferCore = globalThis.EnhancedNetworkTab.ByteBufferCore;
const SecurityScanner = globalThis.EnhancedNetworkTab.SecurityScannerCore;
const FindingPrivacy = globalThis.EnhancedNetworkTab.FindingPrivacyCore;
const RequestInterception =
  globalThis.EnhancedNetworkTab.RequestInterceptionCore;
const MatchReplace = globalThis.EnhancedNetworkTab.MatchReplaceCore;
let inspectedTabs = new Set(); // Track tabs that have DevTools open
let pendingRequests = new Map();
let pendingResponses = new Map();
let requestIdCounter = 0;
let requestIdMap = new Map();
let interceptedRequestIds = new Set();
let interceptedResponseTabIds = new Map();
let pendingResponseHeaderIntercepts = new Map();
let responseInterceptionControls = new Map();

// Extension-origin request tracking handles headers that fetch cannot set directly.
let pendingExtensionRequests = new Map();
const extensionRequestChains =
  RequestInterception.createExtensionRequestChainTracker();
const ruleRedirects = RequestInterception.createRuleRedirectTracker();
let extensionRequestCounter = 0;
let pendingReplacementJobs = new Map();
const replacementResults = RequestInterception.createBoundedResultStore({
  maxEntries: 25,
  maxBytes: 10 * 1024 * 1024,
});
let pendingPromotionId = null;
let seenPromotionIds = [];

const MAX_REQUESTS_PER_TAB = 1000;
const DISPLAY_CAPTURE_LIMIT = 1024 * 1024;
const SECURITY_SCAN_LIMIT = 5 * 1024 * 1024;
const EDITABLE_RESPONSE_LIMIT = 10 * 1024 * 1024;
const SECURITY_FINDING_TTL_MS = 24 * 60 * 60 * 1000;
const REQUEST_INTERCEPT_TIMEOUT_MS = 60 * 1000;
const RESPONSE_HEADER_INTERCEPT_TIMEOUT_MS = 60 * 1000;
const RESPONSE_BODY_INTERCEPT_TIMEOUT_MS = 120 * 1000;
const EXTENSION_REQUEST_TIMEOUT_MS = 30 * 1000;
const REPLACEMENT_CANCEL_CONFIRM_TIMEOUT_MS = 2 * 1000;
const EXTENSION_REQUEST_MARKER_HEADER = "X-Enhanced-Network-Request-ID";
const { armPendingTimeout, markResponseBodyBypass, settlePendingData } =
  globalThis.EnhancedNetworkTab.InterceptionLifecycleCore;

function sanitizeMatchReplaceRules(rules) {
  return MatchReplace.sanitizeRules(rules);
}

function updateResponseCapture(request, collector, isBase64) {
  const captured = collector.toUint8Array();
  const displayBytes = captured.subarray(0, DISPLAY_CAPTURE_LIMIT);

  request.totalBytes = collector.totalBytes;
  request.capturedBytes = Math.min(collector.totalBytes, DISPLAY_CAPTURE_LIMIT);
  request.scannedBytes = Math.min(collector.totalBytes, SECURITY_SCAN_LIMIT);
  request.truncated = collector.totalBytes > DISPLAY_CAPTURE_LIMIT;
  request.responseSize = collector.totalBytes;
  request.isBase64 = isBase64;
  request.responseBody = isBase64
    ? HttpModel.bytesToBase64(displayBytes)
    : new TextDecoder("utf-8").decode(displayBytes);

  return captured;
}

function notifyInterceptionReleased(pendingData, kind, reason) {
  notifyDevTools(
    {
      type: "interceptionReleased",
      requestId: pendingData.id || pendingData.requestId,
      stage: pendingData.stage,
      kind,
      reason,
    },
    pendingData.tabId ?? pendingData.request?.tabId,
  );
}

function resolvePendingRequest(
  originalRequestId,
  pendingData,
  response,
  reason,
) {
  return settlePendingData(pendingData, () => {
    pendingRequests.delete(originalRequestId);
    const request = requests.get(pendingData.id);
    if (request) {
      request.interceptionHandled = true;
      request.intercepted = false;

      if (reason === "timeout") {
        request.statusLine = "Forwarded (Intercept Timeout)";
        notifyDevTools({ type: "updateRequest", request });
      } else if (reason === "disabled") {
        request.statusLine = "Forwarded (Intercept Disabled)";
        notifyDevTools({ type: "updateRequest", request });
      }
    }
    pendingData.resolve(response);
    notifyInterceptionReleased(pendingData, "request", reason);
  });
}

function resolvePendingResponseHeaders(
  requestId,
  pendingData,
  response,
  reason,
) {
  return settlePendingData(pendingData, () => {
    markResponseBodyBypass(pendingData, reason);
    pendingResponseHeaderIntercepts.delete(requestId);
    pendingData.resolve(response);
    notifyInterceptionReleased(pendingData, "response", reason);
  });
}

// ==========================================
// SECURITY SCANNER - Background Implementation
// ==========================================
let securityFindings = [];
const MAX_FINDINGS = 1000;

// Scanning uses the shared SecurityScannerCore loaded before this background entry.

// ==========================================
// LIBRARY SCANNER - Vulnerable JS Library Detection (Retire.js-style)
// ==========================================
let libraryFindings = [];
const MAX_LIBRARY_FINDINGS = 500;

// Runtime vulnerability database refresh. Opt-in (see vulnerabilityDbAutoUpdate);
// the packaged jsrepository.json stays the offline default.
const VULNERABILITY_DB_URL =
  "https://raw.githubusercontent.com/RetireJS/retire.js/refs/heads/master/repository/jsrepository.json";
const VULNERABILITY_DB_STORAGE_KEY = "vulnerabilityDbCache";
const VULNERABILITY_DB_AUTO_UPDATE_KEY = "vulnerabilityDbAutoUpdate";
const VULNERABILITY_DB_MAX_AGE_MS = 7 * 24 * 60 * 60 * 1000;
const VULNERABILITY_DB_MAX_CHARS = 8 * 1024 * 1024;

const LibraryScanner = {
  db: null,
  compiledPatterns: null,
  initialized: false,
  scannedUrls: new Set(), // Cache to avoid re-scanning same URLs

  // Version placeholder used in jsrepository.json
  VERSION_PLACEHOLDER: /§§version§§/g,
  VERSION_PATTERN:
    "([0-9]+(?:\\.[0-9a-z]+)*(?:[._-](?:alpha|beta|rc|pre|preview|dev|snapshot|canary|next|final|ga|release|build|M|SP)[._-]?[0-9]*)?)",

  /**
   * Initialize the scanner by loading jsrepository.json
   */
  async init() {
    if (this.initialized) return true;

    try {
      const url = browser.runtime.getURL("jsrepository.json");
      const response = await fetch(url);
      if (!response.ok) {
        throw new Error(`Failed to load jsrepository.json: ${response.status}`);
      }
      const bundled = await response.json();
      const cached = await this.readCachedDatabase();
      const core = globalThis.EnhancedNetworkTab.LibraryScannerCore;
      const selected = core.selectRepository(bundled, cached?.data ?? null);
      const repositoryErrors = core.validateRepository(selected);
      if (repositoryErrors.length > 0) {
        console.error("[LibraryScanner] Invalid repository:", repositoryErrors);
        return false;
      }
      this.db = selected;
      this.dbSource =
        cached && selected === cached.data ? "downloaded" : "bundled";
      this.dbFetchedAt =
        this.dbSource === "downloaded" ? cached.fetchedAt : null;
      this.compiledPatterns = this.compilePatterns();
      this.initialized = true;
      console.log(
        `[LibraryScanner] Initialized with ${Object.keys(this.db).length} libraries (${this.dbSource})`,
      );
      this.maybeAutoUpdate().catch((err) => {
        console.error(
          "[LibraryScanner] Automatic database update failed:",
          err,
        );
      });
      return true;
    } catch (err) {
      console.error("[LibraryScanner] Initialization failed:", err);
      return false;
    }
  },

  /**
   * Downloaded databases live in storage.local; the packaged file stays read-only.
   */
  async readCachedDatabase() {
    try {
      const stored = await browser.storage.local.get(
        VULNERABILITY_DB_STORAGE_KEY,
      );
      const cached = stored[VULNERABILITY_DB_STORAGE_KEY];
      if (!cached || typeof cached !== "object" || !cached.data) return null;
      return cached;
    } catch (err) {
      console.error("[LibraryScanner] Failed to read cached database:", err);
      return null;
    }
  },

  /**
   * Fetch the upstream database and adopt it only when it validates.
   */
  async updateFromNetwork() {
    const response = await fetch(VULNERABILITY_DB_URL, { cache: "no-cache" });
    if (!response.ok) {
      throw new Error(`Download failed with HTTP ${response.status}`);
    }

    const text = await response.text();
    if (text.length > VULNERABILITY_DB_MAX_CHARS) {
      throw new Error("Downloaded database is unexpectedly large");
    }

    let data;
    try {
      data = JSON.parse(text);
    } catch {
      throw new Error("Downloaded database is not valid JSON");
    }
    const repositoryErrors =
      globalThis.EnhancedNetworkTab.LibraryScannerCore.validateRepository(data);
    if (repositoryErrors.length > 0) {
      throw new Error(`Downloaded database is invalid: ${repositoryErrors[0]}`);
    }

    const fetchedAt = Date.now();
    await browser.storage.local.set({
      [VULNERABILITY_DB_STORAGE_KEY]: { fetchedAt, data },
    });

    this.db = data;
    this.dbSource = "downloaded";
    this.dbFetchedAt = fetchedAt;
    this.compiledPatterns = this.compilePatterns();
    this.clearCache();
    console.log(
      `[LibraryScanner] Database updated from network (${Object.keys(data).length} libraries)`,
    );
    return this.status();
  },

  /**
   * Automatic refresh runs only when opted in and the database is older than a week.
   */
  async maybeAutoUpdate() {
    if (!(await readVulnerabilityDbAutoUpdate())) return null;
    const stale =
      globalThis.EnhancedNetworkTab.LibraryScannerCore.isRepositoryStale(
        this.dbFetchedAt,
        VULNERABILITY_DB_MAX_AGE_MS,
        Date.now(),
      );
    if (!stale) return null;
    return this.updateFromNetwork();
  },

  status() {
    return {
      source: this.dbSource,
      fetchedAt: this.dbFetchedAt,
      libraries: this.db ? Object.keys(this.db).length : 0,
    };
  },

  /**
   * Compile all regex patterns from the database for efficient matching
   */
  compilePatterns() {
    const patterns = {
      filename: [],
      uri: [],
      filecontent: [],
    };

    for (const [libName, libData] of Object.entries(this.db)) {
      if (!libData.extractors) continue;

      // Compile filename patterns
      if (libData.extractors.filename) {
        for (const pattern of libData.extractors.filename) {
          try {
            const regexStr = pattern.replace(
              this.VERSION_PLACEHOLDER,
              this.VERSION_PATTERN,
            );
            patterns.filename.push({
              library: libName,
              regex: new RegExp(regexStr, "i"),
              original: pattern,
            });
          } catch {
            // Skip invalid patterns
          }
        }
      }

      // Compile URI patterns
      if (libData.extractors.uri) {
        for (const pattern of libData.extractors.uri) {
          try {
            const regexStr = pattern.replace(
              this.VERSION_PLACEHOLDER,
              this.VERSION_PATTERN,
            );
            patterns.uri.push({
              library: libName,
              regex: new RegExp(regexStr, "i"),
              original: pattern,
            });
          } catch {
            // Skip invalid patterns
          }
        }
      }

      // Compile filecontent patterns
      if (libData.extractors.filecontent) {
        for (const pattern of libData.extractors.filecontent) {
          try {
            const regexStr = pattern.replace(
              this.VERSION_PLACEHOLDER,
              this.VERSION_PATTERN,
            );
            patterns.filecontent.push({
              library: libName,
              regex: new RegExp(regexStr, "i"),
              original: pattern,
            });
          } catch {
            // Skip invalid patterns
          }
        }
      }
    }

    return patterns;
  },

  /**
   * Parse version string into comparable components
   */
  parseVersion(version) {
    return globalThis.EnhancedNetworkTab.LibraryScannerCore.tokenizeVersion(
      version,
    );
  },

  /**
   * Compare two versions: returns -1 if a < b, 0 if equal, 1 if a > b
   */
  compareVersions(a, b) {
    return globalThis.EnhancedNetworkTab.LibraryScannerCore.compareVersions(
      a,
      b,
    );
  },

  /**
   * Check if a version falls within a vulnerability range
   */
  isVersionVulnerable(version, vuln) {
    return globalThis.EnhancedNetworkTab.LibraryScannerCore.isVersionVulnerable(
      version,
      vuln,
    );
  },

  /**
   * Get vulnerabilities for a specific library version
   */
  getVulnerabilities(library, version) {
    const libData = this.db[library];
    return globalThis.EnhancedNetworkTab.LibraryScannerCore.getVulnerabilitiesForVersion(
      libData,
      version,
    );
  },

  /**
   * Scan URL/filename for library detection
   */
  scanUrl(url) {
    if (!this.initialized || !this.compiledPatterns) return null;

    // Extract filename from URL
    let urlObj;
    try {
      urlObj = new URL(url);
    } catch {
      return null;
    }
    const pathname = urlObj.pathname;
    const filename = pathname.split("/").pop();

    // Try filename patterns first
    for (const pattern of this.compiledPatterns.filename) {
      const match = filename.match(pattern.regex);
      if (match && match[1]) {
        return {
          library: pattern.library,
          version: match[1],
          detectedVia: "filename",
        };
      }
    }

    // Try URI patterns
    for (const pattern of this.compiledPatterns.uri) {
      const match = pathname.match(pattern.regex);
      if (match && match[1]) {
        return {
          library: pattern.library,
          version: match[1],
          detectedVia: "uri",
        };
      }
    }

    return null;
  },

  /**
   * Scan file content for library signatures
   */
  scanContent(content, maxLength = 500000) {
    if (!this.initialized || !this.compiledPatterns) return [];
    if (!content || content.length > maxLength) return [];

    const detected = [];
    const seenLibraries = new Set();

    // Only scan first portion of content for performance
    const scanContent = content.substring(0, maxLength);

    for (const pattern of this.compiledPatterns.filecontent) {
      if (seenLibraries.has(pattern.library)) continue;

      const match = scanContent.match(pattern.regex);
      if (match && match[1]) {
        detected.push({
          library: pattern.library,
          version: match[1],
          detectedVia: "filecontent",
        });
        seenLibraries.add(pattern.library);
      }
    }

    return detected;
  },

  /**
   * Main scan function - checks URL and content for vulnerable libraries
   */
  scan(url, content = null) {
    if (!this.initialized) return null;

    // Check cache
    if (this.scannedUrls.has(url)) return null;

    const findings = [];

    // Scan URL first
    try {
      const urlResult = this.scanUrl(url);
      if (urlResult) {
        const vulns = this.getVulnerabilities(
          urlResult.library,
          urlResult.version,
        );
        if (vulns.length > 0) {
          findings.push({
            library: urlResult.library,
            version: urlResult.version,
            detectedVia: urlResult.detectedVia,
            vulnerabilities: vulns,
            url: url,
          });
        }
      }
    } catch {
      // Invalid URL, skip
    }

    // Scan content if provided and URL didn't yield results
    if (content && findings.length === 0) {
      const contentResults = this.scanContent(content);
      for (const result of contentResults) {
        const vulns = this.getVulnerabilities(result.library, result.version);
        if (vulns.length > 0) {
          findings.push({
            library: result.library,
            version: result.version,
            detectedVia: result.detectedVia,
            vulnerabilities: vulns,
            url: url,
          });
        }
      }
    }

    // Mark URL as scanned
    this.scannedUrls.add(url);

    // Limit cache size
    if (this.scannedUrls.size > 10000) {
      const iterator = this.scannedUrls.values();
      for (let i = 0; i < 5000; i++) {
        this.scannedUrls.delete(iterator.next().value);
      }
    }

    if (findings.length === 0) return null;

    return {
      type: "vulnerableLibraries",
      url: url,
      timestamp: new Date().toISOString(),
      libraries: findings,
      totalFindings: findings.reduce(
        (acc, f) => acc + f.vulnerabilities.length,
        0,
      ),
    };
  },

  /**
   * Check if a URL should be scanned (is a JS file)
   */
  isJavaScriptUrl(url) {
    try {
      const urlObj = new URL(url);
      const pathname = urlObj.pathname.toLowerCase();
      return pathname.endsWith(".js") || pathname.includes(".js?");
    } catch {
      return false;
    }
  },

  /**
   * Clear the URL cache
   */
  clearCache() {
    this.scannedUrls.clear();
  },
};

// Initialize LibraryScanner on startup
LibraryScanner.init().then((success) => {
  if (success) {
    console.log("[LibraryScanner] Ready for scanning");
  }
});

// Update badge with findings count (includes both security and library findings)
function updateBadge() {
  const securityCount = securityFindings.reduce(
    (acc, finding) =>
      acc + (finding.significantFindings ?? finding.totalFindings ?? 0),
    0,
  );
  const libraryCount = libraryFindings.reduce(
    (acc, f) => acc + f.totalFindings,
    0,
  );
  const totalCount = securityCount + libraryCount;
  browser.browserAction.setBadgeText({
    text: totalCount > 0 ? String(totalCount) : "",
  });
  browser.browserAction.setBadgeBackgroundColor({ color: "#dc3545" });
}

// Clear security findings
function findingBelongsToTab(finding, tabId) {
  if (!finding || tabId === null) return tabId === null;
  if (finding.tabId === tabId) return true;
  return requests.get(finding.requestId)?.tabId === tabId;
}

let findingsStorageTimer = null;
function sanitizeSecurityFindingsForStorage() {
  return securityFindings.map((finding) =>
    FindingPrivacy.sanitizeSecurityFinding(finding),
  );
}

function persistSecurityFindingsNow() {
  return browser.storage.local.set({
    securityFindings: sanitizeSecurityFindingsForStorage(),
  });
}

function scheduleFindingsPersistence() {
  if (findingsStorageTimer) clearTimeout(findingsStorageTimer);
  findingsStorageTimer = setTimeout(() => {
    findingsStorageTimer = null;
    browser.storage.local
      .set({
        securityFindings: sanitizeSecurityFindingsForStorage(),
        libraryFindings,
      })
      .catch((error) => {
        console.error("Failed to persist findings:", error);
      });
  }, 250);
}

function clearSecurityFindings(tabId = null) {
  securityFindings =
    tabId === null
      ? []
      : securityFindings.filter(
          (finding) => !findingBelongsToTab(finding, tabId),
        );
  persistSecurityFindingsNow().catch((error) => {
    console.error("Failed to persist cleared security findings:", error);
  });
  updateBadge();
}

// Clear library findings
function clearLibraryFindings(tabId = null) {
  libraryFindings =
    tabId === null
      ? []
      : libraryFindings.filter(
          (finding) => !findingBelongsToTab(finding, tabId),
        );
  LibraryScanner.clearCache();
  browser.storage.local.set({ libraryFindings });
  updateBadge();
}

// Load saved settings and one-time promotion state on startup.
const settingsLoadPromise = browser.storage.local
  .get([
    "interceptSettings",
    "matchReplaceRules",
    "securityFindings",
    "libraryFindings",
    "pendingPromotionId",
    "seenPromotionIds",
  ])
  .then((result) => {
    if (result.interceptSettings) {
      interceptSettings = { ...interceptSettings, ...result.interceptSettings };
    }
    interceptSettings.modifiedRequestAction =
      RequestInterception.normalizeModifiedRequestAction(
        interceptSettings.modifiedRequestAction,
      );
    if (
      interceptSettings.modifiedRequestAction ===
      RequestInterception.MODIFIED_REQUEST_ACTIONS.CANCEL_AND_SEND
    ) {
      interceptSettings.useEarlyInterception = false;
    }
    if (result.matchReplaceRules) {
      matchReplaceRules = sanitizeMatchReplaceRules(result.matchReplaceRules);
    }
    if (result.securityFindings) {
      const now = Date.now();
      securityFindings = result.securityFindings.filter((finding) => {
        const timestamp = Date.parse(finding.timestamp || "");
        return (
          Number.isFinite(timestamp) &&
          now - timestamp <= SECURITY_FINDING_TTL_MS
        );
      });
      if (securityFindings.length !== result.securityFindings.length) {
        persistSecurityFindingsNow().catch((error) => {
          console.error("Failed to remove expired security findings:", error);
        });
      }
    }
    if (result.libraryFindings) {
      libraryFindings = result.libraryFindings;
    }
    pendingPromotionId = result.pendingPromotionId || null;
    seenPromotionIds = Array.isArray(result.seenPromotionIds)
      ? result.seenPromotionIds
      : [];
    updateBadge();
  })
  .catch((err) => {
    console.error("Failed to load settings from storage:", err);
  });

function queueExperimentalPromotion(details) {
  return settingsLoadPromise.then(() => {
    if (
      !RequestInterception.shouldQueuePromotion(
        details,
        seenPromotionIds,
        RequestInterception.PROMOTION_ID,
      )
    ) {
      return false;
    }

    pendingPromotionId = RequestInterception.PROMOTION_ID;
    return browser.storage.local.set({ pendingPromotionId }).then(() => true);
  });
}

// Vulnerability database refresh is opt-in; the packaged copy is the default.
async function readVulnerabilityDbAutoUpdate() {
  try {
    const stored = await browser.storage.local.get(
      VULNERABILITY_DB_AUTO_UPDATE_KEY,
    );
    return stored[VULNERABILITY_DB_AUTO_UPDATE_KEY] === true;
  } catch (error) {
    console.error("Failed to read vulnerability database settings:", error);
    return false;
  }
}

function reportVulnerabilityDbStatus(port, errorMessage = null) {
  LibraryScanner.init()
    .then(() => {
      safePortMessage(port, {
        type: "vulnerabilityDbStatus",
        status: { ...LibraryScanner.status(), error: errorMessage },
      });
    })
    .catch((error) => {
      console.error("Failed to report vulnerability database status:", error);
    });
}

function refreshVulnerabilityDb(port, force) {
  LibraryScanner.init()
    .then(() =>
      force
        ? LibraryScanner.updateFromNetwork()
        : LibraryScanner.maybeAutoUpdate(),
    )
    .then((result) => {
      safePortMessage(port, {
        type: "vulnerabilityDbStatus",
        status: { ...LibraryScanner.status(), refreshed: Boolean(result) },
      });
    })
    .catch((error) => {
      console.error("Vulnerability database update failed:", error);
      reportVulnerabilityDbStatus(port, error.message || String(error));
    });
}

function claimExperimentalPromotion(port) {
  return settingsLoadPromise
    .then(async () => {
      const claim = RequestInterception.claimPromotionState(
        pendingPromotionId,
        seenPromotionIds,
        interceptSettings.modifiedRequestAction,
        RequestInterception.PROMOTION_ID,
      );
      pendingPromotionId = claim.pendingPromotionId;
      seenPromotionIds = claim.seenPromotionIds;
      await browser.storage.local.set({
        pendingPromotionId,
        seenPromotionIds,
      });
      port.postMessage({
        type: "experimentalPromotionClaimed",
        promotion: claim.promotion,
      });
    })
    .catch((error) => {
      console.error("Failed to claim experimental promotion:", error);
      try {
        port.postMessage({
          type: "experimentalPromotionClaimed",
          promotion: null,
        });
      } catch {}
    });
}

// Handle extension installation and version updates
browser.runtime.onInstalled.addListener((details) => {
  if (details.reason === "update" || details.reason === "install") {
    const currentVer = browser.runtime.getManifest().version;
    console.log(
      `[Extension Lifecycle] ${details.reason} to v${currentVer} (previous: ${details.previousVersion || "N/A"})`,
    );
    try {
      localStorage.removeItem("hiddenTypes");
    } catch {}
    browser.storage.local.set({ lastMigratedVersion: currentVer });
  }

  queueExperimentalPromotion(details).catch((error) => {
    console.error("Failed to queue experimental promotion:", error);
  });
});

browser.tabs.onActivated.addListener((activeInfo) => {
  activeTabId = activeInfo.tabId;
  updateIcon(activeInfo.tabId);
});

browser.tabs.onRemoved.addListener((tabId) => {
  releasePendingInterceptions(tabId);
  clearRequestsForTab(tabId);
  ruleRedirects.clearTab(tabId);
  tabSessions.remove(tabId);
  inspectedTabs.delete(tabId);
});

browser.tabs.query({ active: true, currentWindow: true }).then((tabs) => {
  if (tabs[0]) {
    activeTabId = tabs[0].id;
    updateIcon(activeTabId);
  }
});

browser.browserAction.onClicked.addListener((tab) => {
  if (!globalThis.EnhancedNetworkTab.TabSessionCore.isValidTabId(tab?.id))
    return;
  const currentState = tabSessions.get(tab.id, true);
  setTabCaptureEnabled(tab.id, !currentState.captureEnabled);
});

browser.runtime.onInstalled.addListener(() => {
  browser.contextMenus.create({
    id: "toggle-capture",
    title: "Toggle Capture",
    contexts: ["all"],
  });
  browser.contextMenus.create({
    id: "toggle-intercept",
    title: "Toggle Intercept",
    contexts: ["all"],
  });
  browser.contextMenus.create({
    id: "send-to-decoder",
    title: "Send to Decoder",
    contexts: ["selection"],
  });
});

browser.contextMenus.onClicked.addListener((info, tab) => {
  if (!globalThis.EnhancedNetworkTab.TabSessionCore.isValidTabId(tab?.id))
    return;

  if (info.menuItemId === "toggle-capture") {
    const currentState = tabSessions.get(tab.id, true);
    setTabCaptureEnabled(tab.id, !currentState.captureEnabled);
  } else if (info.menuItemId === "toggle-intercept") {
    const currentState = tabSessions.get(tab.id, true);
    setTabInterceptEnabled(tab.id, !currentState.interceptEnabled);
  } else if (info.menuItemId === "send-to-decoder") {
    notifyDevTools(
      {
        type: "sendToDecoder",
        text: info.selectionText,
      },
      tab.id,
    );
  }
});

function setTabCaptureEnabled(tabId, enabled) {
  const previousState = { ...tabSessions.get(tabId, true) };
  const state = tabSessions.setCapture(tabId, enabled);

  if (!state.captureEnabled && previousState.interceptEnabled) {
    releasePendingInterceptions(tabId);
    notifyDevTools({ type: "interceptStateChanged", enabled: false }, tabId);
  }

  updateIcon(tabId);
  notifyDevTools(
    { type: "captureStateChanged", enabled: state.captureEnabled },
    tabId,
  );
  return state;
}

function setTabInterceptEnabled(tabId, enabled) {
  const previousState = { ...tabSessions.get(tabId, true) };
  const state = tabSessions.setIntercept(tabId, enabled);

  if (
    !state.interceptEnabled &&
    (previousState.interceptEnabled || enabled === false)
  ) {
    releasePendingInterceptions(tabId);
  }

  if (state.captureEnabled !== previousState.captureEnabled) {
    notifyDevTools(
      { type: "captureStateChanged", enabled: state.captureEnabled },
      tabId,
    );
  }

  updateIcon(tabId);
  notifyDevTools(
    { type: "interceptStateChanged", enabled: state.interceptEnabled },
    tabId,
  );
  return state;
}

function updateIcon(tabId = activeTabId) {
  if (!globalThis.EnhancedNetworkTab.TabSessionCore.isValidTabId(tabId)) return;
  const state = tabSessions.get(tabId, false) || {
    captureEnabled: false,
    interceptEnabled: false,
  };
  const iconPath = state.captureEnabled
    ? {
        16: "icons/icon16.png",
        32: "icons/icon32.png",
        48: "icons/icon48.png",
        128: "icons/icon128.png",
      }
    : {
        16: "icons/icon16.png",
        32: "icons/icon32.png",
        48: "icons/icon48.png",
        128: "icons/icon128.png",
      };

  browser.browserAction.setIcon({ path: iconPath, tabId });
  browser.browserAction.setTitle({
    tabId,
    title: `Security Proxy - ${state.captureEnabled ? "Capturing" : "Idle"}${state.interceptEnabled ? " (Intercepting)" : ""}`,
  });
}

function getRequestBodyModel(details) {
  return HttpModel.createRequestBodyModel(
    details.requestBody,
    EDITABLE_RESPONSE_LIMIT,
  );
}

function shouldInterceptRequest(details) {
  let shouldIntercept = false;

  if (interceptSettings.includeGET && details.method === "GET") {
    shouldIntercept = true;
  } else if (interceptSettings.methods.includes(details.method)) {
    shouldIntercept = true;
  }

  if (!shouldIntercept) {
    return false;
  }

  if (interceptSettings.excludeExtensions.length > 0) {
    let url;
    try {
      url = new URL(details.url);
    } catch {
      return false;
    }
    const pathname = url.pathname.toLowerCase();
    const hasExcludedExtension = interceptSettings.excludeExtensions.some(
      (ext) => {
        return (
          pathname.endsWith("." + ext.toLowerCase()) ||
          pathname.includes("." + ext.toLowerCase() + "?") ||
          pathname.includes("." + ext.toLowerCase() + "#")
        );
      },
    );

    if (hasExcludedExtension) {
      return false;
    }
  }

  if (interceptSettings.urlPatterns.length > 0) {
    const matchesIncludePattern = interceptSettings.urlPatterns.some(
      (pattern) => {
        try {
          const regex = new RegExp(pattern, "i");
          return regex.test(details.url);
        } catch {
          console.warn("Invalid regex pattern:", pattern);
          return false;
        }
      },
    );

    if (!matchesIncludePattern) {
      return false;
    }
  }

  if (interceptSettings.excludePatterns.length > 0) {
    const matchesExcludePattern = interceptSettings.excludePatterns.some(
      (pattern) => {
        try {
          const regex = new RegExp(pattern, "i");
          return regex.test(details.url);
        } catch {
          console.warn("Invalid regex pattern:", pattern);
          return false;
        }
      },
    );

    if (matchesExcludePattern) {
      return false;
    }
  }

  return true;
}

function requestHasPendingWork(requestId) {
  for (const pending of pendingRequests.values()) {
    if (pending.id === requestId) return true;
  }
  for (const pending of pendingResponses.values()) {
    if (pending.requestId === requestId) return true;
  }
  for (const pending of pendingReplacementJobs.values()) {
    if (pending.requestId === requestId) return true;
  }
  return pendingResponseHeaderIntercepts.has(requestId);
}

function removeRequestRecord(requestId) {
  const request = requests.get(requestId);
  if (!request) return false;

  requests.delete(requestId);
  replacementResults.delete(requestId);
  requestIdMap.delete(request.originalRequestId);

  const previousSecurityCount = securityFindings.length;
  const previousLibraryCount = libraryFindings.length;
  securityFindings = securityFindings.filter(
    (finding) => finding.requestId !== requestId,
  );
  libraryFindings = libraryFindings.filter(
    (finding) => finding.requestId !== requestId,
  );

  if (securityFindings.length !== previousSecurityCount) {
    scheduleFindingsPersistence();
  }
  if (libraryFindings.length !== previousLibraryCount) {
    scheduleFindingsPersistence();
  }
  return true;
}

function enforceRequestLimit(tabId, protectedRequestId = null) {
  const evictionIds =
    globalThis.EnhancedNetworkTab.TabSessionCore.selectRequestIdsForEviction(
      Array.from(requests.entries()),
      tabId,
      MAX_REQUESTS_PER_TAB,
      (requestId) =>
        requestId === protectedRequestId || requestHasPendingWork(requestId),
    );

  for (const requestId of evictionIds) {
    const request = requests.get(requestId);
    if (removeRequestRecord(requestId) && request) {
      notifyDevTools({ type: "requestEvicted", requestId }, request.tabId);
    }
  }
}

browser.webRequest.onBeforeRequest.addListener(
  (details) => {
    const tabState = tabSessions.get(details.tabId, false);

    if (!tabState?.captureEnabled || details.tabId === -1) {
      return {};
    }

    // Scope check
    if (interceptSettings.scopeEnabled) {
      // 1. Check Include Patterns (Whitelist)
      if (interceptSettings.scopePatterns.length > 0) {
        const isInScope = interceptSettings.scopePatterns.some((pattern) => {
          try {
            const regex = new RegExp(pattern, "i");
            return regex.test(details.url);
          } catch {
            console.warn("Invalid regex pattern:", pattern);
            return false;
          }
        });

        if (!isInScope) {
          return {};
        }
      }

      // 2. Check Exclude Patterns (Blacklist)
      if (
        interceptSettings.scopeExcludePatterns &&
        interceptSettings.scopeExcludePatterns.length > 0
      ) {
        const isExcluded = interceptSettings.scopeExcludePatterns.some(
          (pattern) => {
            try {
              const regex = new RegExp(pattern, "i");
              return regex.test(details.url);
            } catch {
              console.warn("Invalid regex pattern:", pattern);
              return false;
            }
          },
        );

        if (isExcluded) {
          return {};
        }
      }
    }

    const requestId = `${details.requestId}_${requestIdCounter++}`;
    requestIdMap.set(details.requestId, requestId);

    // Create request data object early to track modification
    const requestBodyModel = getRequestBodyModel(details);
    const requestData = {
      id: requestId,
      originalRequestId: details.requestId,
      timestamp: Date.now(),
      url: details.url,
      method: details.method,
      type: details.type,
      requestHeaders: [],
      requestBody: requestBodyModel.text,
      requestBodyModel,
      requestSize: 0,
      responseHeaders: [],
      responseBody: "",
      responseSize: 0,
      statusCode: null,
      statusLine: "",
      tabId: details.tabId,
      completed: false,
      intercepted: false,
      interceptionHandled: false,
      shouldIntercept: false,
      wasModified: false,
      autoModified: false,
    };

    // Apply match & replace rules for onBeforeRequest (URL and Body)
    let modifiedDetails = { ...details };
    let wasModified = false;
    let urlModified = false;

    ruleRedirects.begin(details.requestId, details.url, details.tabId);
    if (matchReplaceRules.length > 0) {
      for (const [ruleIndex, rule] of matchReplaceRules.entries()) {
        if (!rule.enabled) continue;

        if (rule.target === "url") {
          const newUrl = applyRuleReplacement(modifiedDetails.url, rule);
          if (newUrl !== modifiedDetails.url) {
            const validation = RequestInterception.validateEditedUrl({
              url: newUrl,
            });
            if (!validation.valid) {
              console.warn(
                "Skipped URL Match & Replace result:",
                validation.errors[0]?.message,
              );
              continue;
            }
            const redirectDecision = ruleRedirects.tryRedirect(
              details.requestId,
              `url-rule-${ruleIndex}`,
              modifiedDetails.url,
              newUrl,
              details.tabId,
            );
            if (!redirectDecision.allowed) continue;

            modifiedDetails.url = newUrl;
            wasModified = true;
            urlModified = true;
          }
        }
      }
    }

    if (wasModified) {
      requestData.wasModified = true;
      requestData.autoModified = true;

      // Priority 1: URL Redirection
      if (urlModified) {
        requestData.originalUrl = details.url;
        requestData.modifiedUrl = modifiedDetails.url;
        requestData.statusLine = "Auto-Redirected (Rule)";
        requestData.statusCode = 307; // Internal redirect code
        requestData.completed = true;

        requests.set(requestId, requestData);
        enforceRequestLimit(details.tabId, requestId);

        notifyDevTools({
          type: "newRequest",
          request: requestData,
        });

        return { redirectUrl: modifiedDetails.url };
      }
    }

    if (tabState.interceptEnabled && shouldInterceptRequest(details)) {
      requestData.shouldIntercept = true;
      requestData.intercepted = true;
      requestData.statusLine = "Intercepted";

      if (interceptSettings.interceptResponses) {
        interceptedRequestIds.add(details.requestId);
        interceptedResponseTabIds.set(details.requestId, details.tabId);
      }

      requests.set(requestId, requestData);
      enforceRequestLimit(details.tabId, requestId);

      notifyDevTools({
        type: "newRequest",
        request: requestData,
      });

      if (interceptSettings.useEarlyInterception) {
        return new Promise((resolve) => {
          const pendingData = {
            ...requestData,
            resolve: resolve,
            originalRequestId: details.requestId,
            createdAt: Date.now(),
            stage: "onBeforeRequest",
          };
          pendingRequests.set(details.requestId, pendingData);
          armPendingTimeout(pendingData, REQUEST_INTERCEPT_TIMEOUT_MS, () => {
            if (pendingRequests.get(details.requestId) !== pendingData) return;
            resolvePendingRequest(
              details.requestId,
              pendingData,
              {},
              "timeout",
            );
          });

          notifyDevTools({
            type: "interceptRequest",
            request: {
              ...requestData,
              stage: "onBeforeRequest",
            },
          });
        });
      }

      return {};
    }

    requests.set(requestId, requestData);
    enforceRequestLimit(details.tabId, requestId);

    notifyDevTools({
      type: "newRequest",
      request: requestData,
    });

    return {};
  },
  { urls: ["<all_urls>"] },
  ["blocking", "requestBody"],
);

function applyHeaderRules(originalHeaders) {
  return MatchReplace.applyHeaderRules(originalHeaders, matchReplaceRules);
}

browser.webRequest.onBeforeSendHeaders.addListener(
  (details) => {
    const originalHeaders = HttpModel.normalizeHeaders(details.requestHeaders);
    const extensionRequestIdHeader = originalHeaders.find(
      (header) =>
        header.name.toLowerCase() ===
        EXTENSION_REQUEST_MARKER_HEADER.toLowerCase(),
    );
    let extensionRequestId = extensionRequestChains.get(details.requestId);

    if (extensionRequestIdHeader) {
      const markedRequest = pendingExtensionRequests.get(
        extensionRequestIdHeader.value,
      );
      if (markedRequest) {
        extensionRequestId = extensionRequestIdHeader.value;
        extensionRequestChains.track(details.requestId, extensionRequestId);
      }
    }

    if (extensionRequestId) {
      const pendingExtensionRequest =
        pendingExtensionRequests.get(extensionRequestId);

      if (pendingExtensionRequest) {
        let forwardedHeaders = HttpModel.normalizeHeaders(
          pendingExtensionRequest.headers,
        ).filter(
          (header) =>
            header.name.toLowerCase() !==
            EXTENSION_REQUEST_MARKER_HEADER.toLowerCase(),
        );
        forwardedHeaders = RequestInterception.sanitizeHeadersForRedirect(
          pendingExtensionRequest.url,
          details.url,
          forwardedHeaders,
        );
        // Firefox calculates framing headers from the actual fetch body. Reuse
        // those values instead of the captured Content-Length, which may be
        // stale after editing. Dropping the calculated value causes Firefox to
        // send an empty upload body for extension-origin Repeater requests.
        forwardedHeaders = HttpModel.replaceHeadersFromSource(
          forwardedHeaders,
          originalHeaders,
          ["content-length", "transfer-encoding"],
        );
        return {
          requestHeaders: forwardedHeaders,
        };
      }
    }

    const requestId = requestIdMap.get(details.requestId);
    if (!requestId) return {};

    const request = requests.get(requestId);

    const { headers: effectiveHeaders, modified: headersModified } =
      applyHeaderRules(originalHeaders);
    const fallbackResponse = headersModified
      ? { requestHeaders: effectiveHeaders }
      : {};

    if (!request) return fallbackResponse;

    request.requestHeaders = HttpModel.cloneHeaders(effectiveHeaders);
    request.requestBodyModel = HttpModel.refineRequestBodyModel(
      request.requestBodyModel,
      effectiveHeaders,
    );
    request.requestBody = request.requestBodyModel.text;
    request.requestSize =
      parseInt(
        HttpModel.getHeaderValue(effectiveHeaders, "content-length"),
        10,
      ) ||
      request.requestBodyModel.byteLength ||
      0;

    if (headersModified) {
      request.wasModified = true;
      request.autoModified = true;
      request.originalHeaders = HttpModel.cloneHeaders(originalHeaders);
      request.modifiedHeaders = HttpModel.cloneHeaders(effectiveHeaders);
      request.statusLine = "Auto-Modified (Headers)";
    }

    notifyDevTools({ type: "updateRequest", request });

    if (
      request.shouldIntercept &&
      !request.interceptionHandled &&
      !pendingRequests.has(details.requestId)
    ) {
      return new Promise((resolve) => {
        request.intercepted = true;
        request.statusLine = "Intercepted (Headers)";

        const pendingData = {
          ...request,
          resolve,
          fallbackResponse,
          originalRequestId: details.requestId,
          createdAt: Date.now(),
          stage: "onBeforeSendHeaders",
        };
        pendingRequests.set(details.requestId, pendingData);
        armPendingTimeout(pendingData, REQUEST_INTERCEPT_TIMEOUT_MS, () => {
          if (pendingRequests.get(details.requestId) !== pendingData) return;
          resolvePendingRequest(
            details.requestId,
            pendingData,
            pendingData.fallbackResponse,
            "timeout",
          );
        });

        notifyDevTools({
          type: "interceptRequest",
          request: { ...request, stage: "onBeforeSendHeaders" },
        });
      });
    }

    return fallbackResponse;
  },
  { urls: ["<all_urls>"] },
  ["blocking", "requestHeaders"],
);

browser.webRequest.onHeadersReceived.addListener(
  (details) => {
    const requestId = requestIdMap.get(details.requestId);
    if (!requestId) return {};

    const request = requests.get(requestId);
    if (!request) return {};

    const shouldInterceptResponse = interceptedRequestIds.has(
      details.requestId,
    );

    const contentType = (
      HttpModel.getHeaderValue(details.responseHeaders, "content-type") || ""
    ).toLowerCase();

    const isTextContent =
      HttpModel.responseBodyEncodingForContentType(contentType) === "text";
    const isImageContent = contentType.includes("image/");
    const isBinaryContent = !isTextContent;
    const responseBodyRules = isTextContent
      ? matchReplaceRules.filter(
          (rule) => rule.enabled && rule.target === "response_body",
        )
      : [];
    const applyResponseBodyRules = responseBodyRules.length > 0;

    // Text and image responses are captured during normal operation. When
    // response interception is explicitly requested, unknown and other
    // binary content types are also handled byte-for-byte as Base64.
    if (shouldInterceptResponse || isTextContent || isImageContent) {
      const filter = browser.webRequest.filterResponseData(details.requestId);
      const decoder = new TextDecoder("utf-8");
      const captureCollector = ByteBufferCore.createBoundedCollector(
        isTextContent ? SECURITY_SCAN_LIMIT : DISPLAY_CAPTURE_LIMIT,
      );

      if (shouldInterceptResponse) {
        const responseControl = {
          bypassBody: false,
          tabId: request.tabId,
        };
        responseInterceptionControls.set(details.requestId, responseControl);
        const editableBuffer = ByteBufferCore.createWholeChunkBuffer(
          EDITABLE_RESPONSE_LIMIT,
        );
        let bypassReason = null;

        filter.ondata = (event) => {
          captureCollector.add(event.data);

          if (responseControl.bypassBody) {
            const buffered = editableBuffer.drain();
            if (buffered.byteLength > 0) filter.write(buffered);
            filter.write(event.data);
            return;
          }

          if (!editableBuffer.tryAdd(event.data)) {
            const buffered = editableBuffer.drain();
            if (buffered.byteLength > 0) filter.write(buffered);
            filter.write(event.data);
            responseControl.bypassBody = true;
            bypassReason = "size-limit";
          }
        };

        filter.onerror = (event) => {
          console.error("Intercepted response filter failed:", event.error);

          const pendingHeader = pendingResponseHeaderIntercepts.get(requestId);
          if (pendingHeader?.originalRequestId === details.requestId) {
            resolvePendingResponseHeaders(
              requestId,
              pendingHeader,
              {},
              "filter-error",
            );
          }

          const pendingBody = pendingResponses.get(details.requestId);
          if (pendingBody) {
            settlePendingData(pendingBody, () => {
              pendingResponses.delete(details.requestId);
              try {
                pendingBody.filter.close();
              } catch {}
              notifyInterceptionReleased(
                pendingBody,
                "response",
                "filter-error",
              );
            });
          }

          responseControl.bypassBody = true;
          responseInterceptionControls.delete(details.requestId);
          interceptedRequestIds.delete(details.requestId);
          interceptedResponseTabIds.delete(details.requestId);
        };

        filter.onstop = () => {
          let combinedData = null;
          try {
            if (responseControl.bypassBody) {
              try {
                const buffered = editableBuffer.drain();
                if (buffered.byteLength > 0) filter.write(buffered);
                filter.close();
                updateResponseCapture(
                  request,
                  captureCollector,
                  isBinaryContent,
                );
                if (bypassReason === "size-limit") {
                  request.responseInterceptSkipped = "size-limit";
                  request.statusLine =
                    "Response Forwarded (Over 10 MiB Edit Limit)";
                }
                notifyDevTools({ type: "updateRequest", request });
              } finally {
                responseInterceptionControls.delete(details.requestId);
                interceptedRequestIds.delete(details.requestId);
                interceptedResponseTabIds.delete(details.requestId);
              }
              return;
            }

            combinedData = editableBuffer.drain();
            updateResponseCapture(request, captureCollector, isBinaryContent);

            let bodyContent;
            if (isBinaryContent) {
              bodyContent = HttpModel.bytesToBase64(combinedData);
            } else {
              bodyContent = decoder.decode(combinedData);
            }

            const responseInterceptData = {
              requestId: requestId,
              originalRequestId: details.requestId,
              filter: filter,
              responseHeaders: details.responseHeaders,
              responseBody: bodyContent,
              originalBytes: combinedData,
              statusCode: details.statusCode,
              statusLine: details.statusLine,
              request: request,
              tabId: request.tabId,
              isBase64: isBinaryContent,
              createdAt: Date.now(),
              stage: "responseBody",
            };

            pendingResponses.set(details.requestId, responseInterceptData);
            responseInterceptionControls.delete(details.requestId);
            armPendingTimeout(
              responseInterceptData,
              RESPONSE_BODY_INTERCEPT_TIMEOUT_MS,
              () => {
                if (
                  pendingResponses.get(details.requestId) !==
                  responseInterceptData
                )
                  return;

                settlePendingData(responseInterceptData, () => {
                  pendingResponses.delete(details.requestId);
                  try {
                    responseInterceptData.filter.write(
                      getOriginalResponseData(responseInterceptData),
                    );
                    responseInterceptData.filter.close();
                  } catch (error) {
                    console.error(
                      "Failed to release timed out response:",
                      error,
                    );
                    try {
                      responseInterceptData.filter.close();
                    } catch {}
                  }
                  notifyInterceptionReleased(
                    responseInterceptData,
                    "response",
                    "timeout",
                  );
                });
              },
            );
            interceptedRequestIds.delete(details.requestId);
            interceptedResponseTabIds.delete(details.requestId);

            notifyDevTools({
              type: "interceptResponse",
              response: {
                requestId: requestId,
                statusCode: details.statusCode,
                statusLine: details.statusLine,
                responseHeaders: request.responseHeaders,
                responseBody: bodyContent,
                isBase64: isBinaryContent,
                stage: "responseBody",
              },
            });
          } catch (e) {
            console.error("Failed to decode response for interception:", e);
            const pendingBody = pendingResponses.get(details.requestId);
            if (pendingBody?.filter === filter) {
              settlePendingData(pendingBody, () => {
                pendingResponses.delete(details.requestId);
                writeOriginalResponseFailSafe(
                  pendingBody,
                  "response interception setup failure",
                );
                notifyInterceptionReleased(
                  pendingBody,
                  "response",
                  "interception-setup-failed",
                );
              });
            } else {
              const buffered = combinedData || editableBuffer.drain();
              writeOriginalResponseFailSafe(
                { filter, originalBytes: buffered },
                "response interception setup failure",
              );
            }
            responseInterceptionControls.delete(details.requestId);
            interceptedRequestIds.delete(details.requestId);
            interceptedResponseTabIds.delete(details.requestId);
          }
        };

        return new Promise((resolve) => {
          const pendingHeaderData = {
            requestId: requestId,
            originalRequestId: details.requestId,
            resolve: resolve,
            filter: filter,
            tabId: request.tabId,
            responseHeaders: details.responseHeaders,
            statusCode: details.statusCode,
            statusLine: details.statusLine,
            createdAt: Date.now(),
            stage: "responseHeaders",
            request: request,
            responseControl,
          };
          pendingResponseHeaderIntercepts.set(requestId, pendingHeaderData);
          armPendingTimeout(
            pendingHeaderData,
            RESPONSE_HEADER_INTERCEPT_TIMEOUT_MS,
            () => {
              if (
                pendingResponseHeaderIntercepts.get(requestId) !==
                pendingHeaderData
              )
                return;
              resolvePendingResponseHeaders(
                requestId,
                pendingHeaderData,
                {},
                "timeout",
              );
            },
          );

          notifyDevTools({
            type: "interceptResponse",
            response: {
              requestId: requestId,
              statusCode: details.statusCode,
              statusLine: details.statusLine,
              responseHeaders: details.responseHeaders,
              stage: "responseHeaders",
            },
          });
        });
      } else {
        const ruleBuffer = applyResponseBodyRules
          ? ByteBufferCore.createWholeChunkBuffer(EDITABLE_RESPONSE_LIMIT)
          : null;
        let responseRulesBypassed = false;

        filter.ondata = (event) => {
          captureCollector.add(event.data);

          if (!applyResponseBodyRules) {
            filter.write(event.data);
          } else if (responseRulesBypassed) {
            filter.write(event.data);
          } else if (!ruleBuffer.tryAdd(event.data)) {
            const buffered = ruleBuffer.drain();
            if (buffered.byteLength > 0) filter.write(buffered);
            filter.write(event.data);
            responseRulesBypassed = true;
          }
        };

        filter.onstop = () => {
          try {
            const capturedData = updateResponseCapture(
              request,
              captureCollector,
              isBinaryContent,
            );

            if (isTextContent) {
              let text = decoder.decode(capturedData);

              // Apply Match & Replace rules targeting the Response Body
              let responseModified = false;
              if (applyResponseBodyRules && !responseRulesBypassed) {
                const ruleBytes = ruleBuffer.drain();
                let ruleText = decoder.decode(ruleBytes);
                for (const rule of responseBodyRules) {
                  const replaced = applyRuleReplacement(ruleText, rule);
                  if (replaced !== ruleText) {
                    ruleText = replaced;
                    responseModified = true;
                  }
                }
                if (responseModified) {
                  const modifiedBytes = new TextEncoder().encode(ruleText);
                  if (modifiedBytes.byteLength > EDITABLE_RESPONSE_LIMIT) {
                    filter.write(ruleBytes);
                    responseModified = false;
                    request.responseRuleSkipped = "replacement-size-limit";
                    request.statusLine =
                      "Response Rule Skipped (Output Over 10 MiB Limit)";
                  } else {
                    filter.write(modifiedBytes);
                    text = decoder.decode(
                      modifiedBytes.subarray(0, SECURITY_SCAN_LIMIT),
                    );
                    request.responseBody = decoder.decode(
                      modifiedBytes.subarray(0, DISPLAY_CAPTURE_LIMIT),
                    );
                    request.totalBytes = modifiedBytes.byteLength;
                    request.responseSize = modifiedBytes.byteLength;
                    request.capturedBytes = Math.min(
                      modifiedBytes.byteLength,
                      DISPLAY_CAPTURE_LIMIT,
                    );
                    request.truncated =
                      modifiedBytes.byteLength > DISPLAY_CAPTURE_LIMIT;
                  }
                } else {
                  filter.write(ruleBytes);
                }
              } else if (responseRulesBypassed) {
                request.responseRuleSkipped = "size-limit";
                request.statusLine =
                  "Response Rule Skipped (Over 10 MiB Limit)";
              }
              if (responseModified) {
                request.wasModified = true;
                request.autoModified = true;
                request.responseModified = true;
                request.statusLine = "Response Modified (Rule)";
              }

              // Helper to extract referer header or document URL
              const getRequestReferer = (req, det) => {
                let ref = "";
                if (req && req.requestHeaders) {
                  ref =
                    HttpModel.getHeaderValue(req.requestHeaders, "referer") ||
                    "";
                }
                if (!ref && det) {
                  ref = det.documentUrl || det.originUrl || "";
                }
                return ref;
              };

              const getHostname = (u) => {
                if (!u) return "";
                try {
                  return new URL(u).hostname;
                } catch {
                  return "";
                }
              };

              // Background security scanning - runs even when DevTools is closed
              if (SecurityScanner.isScannable(contentType)) {
                const scanResults = SecurityScanner.scan(text, details.url);
                if (scanResults && scanResults.totalFindings > 0) {
                  const refUrl = getRequestReferer(request, details);
                  scanResults.requestId = request.id;
                  scanResults.tabId = request.tabId;
                  scanResults.domain = getHostname(details.url);
                  scanResults.referer = refUrl;
                  scanResults.refererDomain = getHostname(refUrl);
                  securityFindings.push(scanResults);

                  // Limit stored findings
                  if (securityFindings.length > MAX_FINDINGS) {
                    securityFindings = securityFindings.slice(-MAX_FINDINGS);
                  }

                  // Persist findings to storage
                  scheduleFindingsPersistence();

                  // Update badge
                  updateBadge();

                  // Notify DevTools if connected
                  notifyDevTools({
                    type: "securityFinding",
                    finding: scanResults,
                  });
                }
              }

              // Background library scanning - detect vulnerable JS libraries
              if (LibraryScanner.initialized) {
                const isJs =
                  contentType &&
                  (contentType.includes("javascript") ||
                    contentType.includes("text/javascript") ||
                    LibraryScanner.isJavaScriptUrl(details.url));

                if (isJs) {
                  const libResults = LibraryScanner.scan(details.url, text);
                  if (libResults && libResults.totalFindings > 0) {
                    const refUrl = getRequestReferer(request, details);
                    libResults.requestId = request.id;
                    libResults.tabId = request.tabId;
                    libResults.domain = getHostname(details.url);
                    libResults.referer = refUrl;
                    libResults.refererDomain = getHostname(refUrl);
                    libraryFindings.push(libResults);

                    // Limit stored findings
                    if (libraryFindings.length > MAX_LIBRARY_FINDINGS) {
                      libraryFindings = libraryFindings.slice(
                        -MAX_LIBRARY_FINDINGS,
                      );
                    }

                    // Persist findings to storage
                    scheduleFindingsPersistence();

                    // Update badge
                    updateBadge();

                    // Notify DevTools if connected
                    notifyDevTools({
                      type: "libraryFinding",
                      finding: libResults,
                    });
                  }
                }
              }
            }

            filter.close();

            notifyDevTools({
              type: "updateRequest",
              request: request,
            });
          } catch (e) {
            console.error("Failed to decode response:", e);
            try {
              filter.close();
            } catch {}
          }
        };
      }
    }

    return applyResponseBodyRules
      ? {
          responseHeaders: HttpModel.removeHeader(
            details.responseHeaders,
            "content-length",
          ),
        }
      : {};
  },
  {
    urls: ["<all_urls>"],
    types: [
      "xmlhttprequest",
      "main_frame",
      "sub_frame",
      "image",
      "media",
      "font",
      "script",
      "stylesheet",
      "other",
    ],
  },
  ["blocking", "responseHeaders"],
);

browser.webRequest.onResponseStarted.addListener(
  (details) => {
    const requestId = requestIdMap.get(details.requestId);
    if (!requestId) return;

    const request = requests.get(requestId);
    if (request) {
      request.statusCode = details.statusCode;
      request.statusLine = details.statusLine;
      request.responseHeaders = HttpModel.cloneHeaders(details.responseHeaders);
      request.responseSize =
        parseInt(
          HttpModel.getHeaderValue(details.responseHeaders, "content-length"),
          10,
        ) || 0;
      notifyDevTools({
        type: "updateRequest",
        request: request,
      });
    }
  },
  { urls: ["<all_urls>"] },
  ["responseHeaders"],
);

browser.webRequest.onCompleted.addListener(
  (details) => {
    extensionRequestChains.clear(details.requestId);
    ruleRedirects.clear(details.requestId);
    const requestId = requestIdMap.get(details.requestId);
    const replacementJob = pendingReplacementJobs.get(details.requestId);
    requestIdMap.delete(details.requestId);
    interceptedRequestIds.delete(details.requestId);
    interceptedResponseTabIds.delete(details.requestId);
    responseInterceptionControls.delete(details.requestId);

    if (!requestId) return;

    const request = requests.get(requestId);
    if (replacementJob && !replacementJob.started) {
      replacementJob.failOnce("original-completed");
    }
    if (request) {
      request.completed = replacementJob?.started
        ? ["succeeded", "failed", "timeout"].includes(request.replacementState)
        : true;
      notifyDevTools({
        type: "updateRequest",
        request: request,
      });
    }
  },
  { urls: ["<all_urls>"] },
);

browser.webRequest.onErrorOccurred.addListener(
  (details) => {
    extensionRequestChains.clear(details.requestId);
    ruleRedirects.clear(details.requestId);
    const requestId = requestIdMap.get(details.requestId);
    const replacementJob = pendingReplacementJobs.get(details.requestId);
    if (replacementJob) {
      replacementJob.startOnce("original-cancelled");
    }
    requestIdMap.delete(details.requestId);
    interceptedRequestIds.delete(details.requestId);
    interceptedResponseTabIds.delete(details.requestId);
    responseInterceptionControls.delete(details.requestId);

    if (!requestId) return;

    const request = requests.get(requestId);
    if (request) {
      request.statusCode = 0;
      request.originalNetworkError = details.error;
      request.originalCompleted = true;
      if (
        !["cancelled", "cancellation-unconfirmed"].includes(
          request.originalOutcome,
        )
      ) {
        request.statusLine = `Error: ${details.error}`;
        request.completed = true;
      }
      notifyDevTools({
        type: "updateRequest",
        request: request,
      });
    }
  },
  { urls: ["<all_urls>"] },
);

function getRequestsForTab(tabId) {
  return Array.from(requests.values()).filter(
    (request) => request.tabId === tabId,
  );
}

function getFindingsForTab(findings, tabId) {
  return findings.filter((finding) => findingBelongsToTab(finding, tabId));
}

function sendInitialState(port, tabId) {
  const state = tabSessions.get(tabId, true);
  safePortMessage(port, {
    type: "initialState",
    captureEnabled: state.captureEnabled,
    interceptEnabled: state.interceptEnabled,
    interceptSettings,
    requests: getRequestsForTab(tabId),
    securityFindings: getFindingsForTab(securityFindings, tabId),
    libraryFindings: getFindingsForTab(libraryFindings, tabId),
  });
}

function clearRequestsForTab(tabId) {
  releasePendingInterceptions(tabId);
  const removedRequestIds = new Set();

  for (const [requestId, request] of requests.entries()) {
    if (request.tabId !== tabId) continue;
    removedRequestIds.add(requestId);
    replacementResults.delete(requestId);
    requests.delete(requestId);
  }

  for (const [browserRequestId, requestId] of requestIdMap.entries()) {
    if (removedRequestIds.has(requestId)) {
      requestIdMap.delete(browserRequestId);
    }
  }

  clearSecurityFindings(tabId);
  clearLibraryFindings(tabId);
}

browser.runtime.onConnect.addListener((port) => {
  if (port.name !== "devtools-panel") return;

  const record = devtoolsPorts.register(port);

  port.onMessage.addListener((msg) => {
    handleDevToolsMessage(msg, record);
  });

  port.onDisconnect.addListener(() => {
    const disconnectedRecord = devtoolsPorts.unregister(record.id);
    const tabId = disconnectedRecord?.inspectedTabId;

    if (
      globalThis.EnhancedNetworkTab.TabSessionCore.isValidTabId(tabId) &&
      !devtoolsPorts.hasTab(tabId)
    ) {
      inspectedTabs.delete(tabId);
      // A pending intercept has no UI owner after the final DevTools panel
      // disconnects. Keep capture enabled, but stop interception so both the
      // current queue and future requests continue without waiting for a
      // panel that can no longer answer.
      setTabInterceptEnabled(tabId, false);
    }
  });
});

function handleDevToolsMessage(msg, portRecord) {
  if (msg.type === "setInspectedTab") {
    const attachedRecord = devtoolsPorts.attachTab(portRecord.id, msg.tabId);
    if (!attachedRecord) return;

    inspectedTabs.add(msg.tabId);
    settingsLoadPromise.then(() => {
      sendInitialState(attachedRecord.port, msg.tabId);
    });
    updateIcon(msg.tabId);
    return;
  }

  if (msg.type === "getVulnerabilityDbStatus") {
    reportVulnerabilityDbStatus(portRecord.port);
    return;
  }

  if (msg.type === "updateVulnerabilityDb") {
    refreshVulnerabilityDb(portRecord.port, msg.force === true);
    return;
  }

  const tabId = portRecord.inspectedTabId;
  if (!globalThis.EnhancedNetworkTab.TabSessionCore.isValidTabId(tabId)) return;
  const port = portRecord.port;

  switch (msg.type) {
    case "toggleCapture":
      setTabCaptureEnabled(tabId, msg.enabled);
      break;

    case "toggleIntercept":
      setTabInterceptEnabled(tabId, msg.enabled);
      break;

    case "clearRequests":
      clearRequestsForTab(tabId);
      notifyDevTools({ type: "requestsCleared" }, tabId);
      break;

    case "forwardRequest":
      if (requests.get(msg.requestId)?.tabId === tabId) {
        handleForwardRequest(msg.requestId, msg.modifiedRequest, port);
      }
      break;

    case "dropRequest":
      if (requests.get(msg.requestId)?.tabId === tabId) {
        handleDropRequest(msg.requestId);
      }
      break;

    case "sendRepeaterRequest":
      handleRepeaterRequest(msg.requestData, port, msg.requestId);
      break;

    case "getReplacementResult": {
      const request = requests.get(msg.requestId);
      if (request?.tabId !== tabId) break;
      safePortMessage(port, {
        type: "replacementResult",
        requestId: msg.requestId,
        requestData: getModifiedRequestData(request),
        result: replacementResults.get(msg.requestId),
      });
      break;
    }

    case "claimExperimentalPromotion":
      claimExperimentalPromotion(port);
      break;

    case "updateInterceptSettings":
      interceptSettings = {
        ...interceptSettings,
        ...msg.settings,
        modifiedRequestAction:
          RequestInterception.normalizeModifiedRequestAction(
            msg.settings?.modifiedRequestAction ??
              interceptSettings.modifiedRequestAction,
          ),
      };
      if (
        interceptSettings.modifiedRequestAction ===
        RequestInterception.MODIFIED_REQUEST_ACTIONS.CANCEL_AND_SEND
      ) {
        interceptSettings.useEarlyInterception = false;
      }
      // Save to storage for persistence
      browser.storage.local
        .set({ interceptSettings: interceptSettings })
        .catch((err) => {
          console.error("Failed to save intercept settings:", err);
        });
      notifyDevTools({
        type: "interceptSettingsChanged",
        settings: interceptSettings,
      });
      break;

    case "updateMatchReplaceRules":
      matchReplaceRules = sanitizeMatchReplaceRules(msg.rules);
      browser.storage.local
        .set({ matchReplaceRules: matchReplaceRules })
        .catch((err) => {
          console.error("Failed to save match replace rules:", err);
        });
      break;

    case "getInterceptSettings":
      port.postMessage({
        type: "interceptSettingsResponse",
        settings: interceptSettings,
      });
      break;

    case "getSecurityFindings":
      port.postMessage({
        type: "securityFindingsResponse",
        findings: getFindingsForTab(securityFindings, tabId),
      });
      break;

    case "clearSecurityFindings":
      clearSecurityFindings(tabId);
      notifyDevTools({ type: "securityFindingsCleared" }, tabId);
      break;

    case "getLibraryFindings":
      port.postMessage({
        type: "libraryFindingsResponse",
        findings: getFindingsForTab(libraryFindings, tabId),
      });
      break;

    case "clearLibraryFindings":
      clearLibraryFindings(tabId);
      notifyDevTools({ type: "libraryFindingsCleared" }, tabId);
      break;

    case "forwardResponse":
      if (requests.get(msg.requestId)?.tabId === tabId) {
        handleForwardResponse(msg.requestId, msg.modifiedResponse, port);
      }
      break;

    case "dropResponse":
      if (requests.get(msg.requestId)?.tabId === tabId) {
        handleDropResponse(msg.requestId);
      }
      break;

    case "disableIntercept":
      handleDisableIntercept(tabId);
      break;
  }
}

function moveRequestEditsToRepeater(request, modifiedRequest, port) {
  let draftHeaders = HttpModel.normalizeHeaders(modifiedRequest.headers);
  if (modifiedRequest.body !== request.requestBody) {
    draftHeaders = HttpModel.removeHeader(draftHeaders, "content-length");
  }

  request.intercepted = false;
  request.interceptionHandled = true;
  request.repeaterDraftCreated = true;
  request.statusLine = "Original Forwarded; Edits Moved to Repeater";
  request.modifiedUrl = modifiedRequest.url;
  request.modifiedMethod = modifiedRequest.method;
  request.modifiedHeaders = HttpModel.cloneHeaders(draftHeaders);
  request.modifiedBody = modifiedRequest.body;
  request.modifiedBodyEncoding = modifiedRequest.bodyEncoding || "text";

  notifyDevTools({ type: "updateRequest", request });
  safePortMessage(port, {
    type: "repeaterDraft",
    requestData: {
      ...modifiedRequest,
      headers: draftHeaders,
    },
  });
}

function recordModifiedRequest(request, pending, modifiedRequest) {
  request.originalUrl = pending.url;
  request.originalMethod = pending.method;
  request.originalHeaders = HttpModel.cloneHeaders(pending.requestHeaders);
  request.originalBody = pending.requestBody;
  request.originalBodyEncoding = HttpModel.bodyEditorEncoding(
    request.requestBodyModel,
  );
  request.modifiedUrl = modifiedRequest.url;
  request.modifiedMethod = modifiedRequest.method;
  request.modifiedHeaders = HttpModel.normalizeHeaders(modifiedRequest.headers);
  request.modifiedBody = modifiedRequest.body;
  request.modifiedBodyEncoding = modifiedRequest.bodyEncoding || "text";
  request.wasModified = true;
}

function getModifiedRequestData(request) {
  return {
    method: request.modifiedMethod || request.method,
    url: request.modifiedUrl || request.url,
    headers: HttpModel.cloneHeaders(
      request.modifiedHeaders || request.requestHeaders,
    ),
    body:
      request.modifiedBody !== undefined
        ? request.modifiedBody
        : request.requestBody,
    bodyEncoding:
      request.modifiedBodyEncoding ||
      HttpModel.bodyEditorEncoding(request.requestBodyModel),
    bodyEditable: true,
    bodyReplayable: true,
  };
}

async function performReplacementRequest(job, trigger) {
  if (job.fallbackTimer) {
    clearTimeout(job.fallbackTimer);
    job.fallbackTimer = null;
  }

  const request = requests.get(job.requestId);
  if (request) {
    request.replacementState = "sending";
    request.replacementTrigger = trigger;
    request.statusLine = "Original Cancelled; Sending Edited Request";
    notifyDevTools({ type: "updateRequest", request });
  }
  safePortMessage(job.port, {
    type: "replacementStarted",
    requestId: job.requestId,
    requestData: job.requestData,
  });

  try {
    const response = await sendExtensionRequest(
      job.requestData,
      "intercept-replacement",
    );
    if (request) {
      request.replacementState = "succeeded";
      request.replacementStatusCode = response.status;
      request.replacementDuration = response.duration;
      request.replacementFinalUrl = response.finalUrl;
      request.statusLine = `Edited Request Sent (${response.status})`;
      request.completed = true;
      notifyDevTools({ type: "updateRequest", request });
    }
    replacementResults.set(job.requestId, {
      state: "succeeded",
      response,
      storedAt: Date.now(),
    });
    safePortMessage(job.port, {
      type: "replacementResponse",
      requestId: job.requestId,
      response,
    });
  } catch (error) {
    const errorMessage = extensionRequestErrorMessage(error, "Edited");
    const timedOut = error?.name === "AbortError";
    if (request) {
      request.replacementState = timedOut ? "timeout" : "failed";
      request.replacementError = errorMessage;
      request.statusLine = timedOut
        ? "Edited Request Timed Out"
        : "Edited Request Failed";
      request.completed = true;
      notifyDevTools({ type: "updateRequest", request });
    }
    replacementResults.set(job.requestId, {
      state: timedOut ? "timeout" : "failed",
      error: errorMessage,
      storedAt: Date.now(),
    });
    safePortMessage(job.port, {
      type: "replacementError",
      requestId: job.requestId,
      error: errorMessage,
    });
  } finally {
    pendingReplacementJobs.delete(job.originalRequestId);
  }
}

function failReplacementBeforeSend(job, reason) {
  if (job.fallbackTimer) {
    clearTimeout(job.fallbackTimer);
    job.fallbackTimer = null;
  }
  pendingReplacementJobs.delete(job.originalRequestId);
  const request = requests.get(job.requestId);
  const originalCompleted = reason === "original-completed";
  const error = originalCompleted
    ? "The original request completed before Firefox confirmed cancellation. The edited request was not sent to avoid a duplicate."
    : "Firefox did not confirm cancellation in time; the edited request was not sent to avoid a duplicate.";
  if (request) {
    request.originalOutcome = originalCompleted
      ? "completed-unexpectedly"
      : "cancellation-unconfirmed";
    request.replacementState = "failed";
    request.replacementError = error;
    request.statusLine = originalCompleted
      ? "Original Was Not Cancelled; Edited Request Not Sent"
      : "Cancellation Unconfirmed; Edited Request Not Sent";
    request.completed = true;
    notifyDevTools({ type: "updateRequest", request });
  }
  replacementResults.set(job.requestId, {
    state: "failed",
    error,
    storedAt: Date.now(),
  });
  safePortMessage(job.port, {
    type: "replacementError",
    requestId: job.requestId,
    error,
  });
}

function queueReplacementRequest(
  originalRequestId,
  pending,
  request,
  modifiedRequest,
  port,
) {
  const job = {
    originalRequestId,
    requestId: request.id,
    requestData: modifiedRequest,
    port,
    fallbackTimer: null,
    started: false,
    startOnce: null,
    failOnce: null,
  };
  const startController = RequestInterception.createReplacementStartController(
    (trigger) => {
      job.started = true;
      void performReplacementRequest(job, trigger);
    },
    (reason) => failReplacementBeforeSend(job, reason),
  );
  job.startOnce = (reason) => startController.confirm(reason);
  job.failOnce = (reason) => startController.fail(reason);
  pendingReplacementJobs.set(originalRequestId, job);

  request.originalOutcome = "cancelled";
  request.replacementState = "queued";
  request.extensionOrigin = true;
  request.statusCode = 0;
  request.statusLine = "Cancelling Original; Edited Request Queued";
  recordModifiedRequest(request, pending, modifiedRequest);
  notifyDevTools({ type: "updateRequest", request });
  safePortMessage(port, {
    type: "replacementQueued",
    requestId: request.id,
    requestData: modifiedRequest,
  });

  interceptedRequestIds.delete(originalRequestId);
  interceptedResponseTabIds.delete(originalRequestId);
  responseInterceptionControls.delete(originalRequestId);
  resolvePendingRequest(
    originalRequestId,
    pending,
    { cancel: true },
    "cancelled-for-replacement",
  );

  job.fallbackTimer = setTimeout(() => {
    if (pendingReplacementJobs.get(originalRequestId) !== job) return;
    job.failOnce("confirmation-timeout");
  }, REPLACEMENT_CANCEL_CONFIRM_TIMEOUT_MS);
}

async function handleForwardRequest(requestId, modifiedRequest, port) {
  let originalRequestId = null;
  let pending = null;

  for (const [key, value] of pendingRequests.entries()) {
    if (value.id === requestId) {
      originalRequestId = key;
      pending = value;
      break;
    }
  }

  if (!pending?.resolve) return;

  const request = requests.get(requestId);
  if (!request || !modifiedRequest) return;

  const replayCandidate = {
    ...modifiedRequest,
    bodyReplayable: request.requestBodyModel?.replayable !== false,
    bodyUnavailableReason: request.requestBodyModel?.reason,
  };
  const decision = RequestInterception.decideInterceptAction(
    pending,
    replayCandidate,
    {
      modifiedRequestAction: interceptSettings.modifiedRequestAction,
      maxBodyBytes: EDITABLE_RESPONSE_LIMIT,
    },
  );

  if (decision.action === "reject-edit") {
    safePortMessage(port, {
      type: "interceptValidationError",
      requestId,
      errors: decision.validation.errors,
    });
    return;
  }

  if (decision.edits.anyChanged) {
    recordModifiedRequest(request, pending, replayCandidate);
  }

  switch (decision.action) {
    case "create-repeater-draft":
      resolvePendingRequest(
        originalRequestId,
        pending,
        pending.fallbackResponse || {},
        "repeater-draft",
      );
      moveRequestEditsToRepeater(request, replayCandidate, port);
      return;

    case "redirect":
      request.statusLine = "Redirecting (Early Intercept)";
      notifyDevTools({ type: "updateRequest", request });
      resolvePendingRequest(
        originalRequestId,
        pending,
        { redirectUrl: replayCandidate.url },
        "redirected",
      );
      return;

    case "apply-headers":
      resolvePendingRequest(
        originalRequestId,
        pending,
        { requestHeaders: HttpModel.normalizeHeaders(replayCandidate.headers) },
        "headers-modified",
      );
      request.statusLine = "Forwarded (Headers Modified)";
      notifyDevTools({ type: "updateRequest", request });
      return;

    case "cancel-and-send":
      queueReplacementRequest(
        originalRequestId,
        pending,
        request,
        replayCandidate,
        port,
      );
      return;

    default:
      resolvePendingRequest(
        originalRequestId,
        pending,
        pending.fallbackResponse || {},
        "forwarded",
      );
      request.statusLine =
        pending.stage === "onBeforeRequest"
          ? "Forwarded (Early Intercept)"
          : "Forwarded (Unmodified)";
      notifyDevTools({ type: "updateRequest", request });
  }
}

function handleDropRequest(requestId) {
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
    if (request) {
      request.intercepted = false;
      request.statusLine = "Dropped";
      request.statusCode = 0;
      request.completed = true;
      notifyDevTools({
        type: "updateRequest",
        request: request,
      });
    }

    resolvePendingRequest(
      originalRequestId,
      pending,
      { cancel: true },
      "dropped",
    );
  }
}

function sendResponseValidationError(port, requestId, errors) {
  safePortMessage(port, {
    type: "responseInterceptValidationError",
    requestId,
    errors,
  });
}

function prepareModifiedResponseData(pending, modifiedResponse) {
  if (!modifiedResponse.bodyEdited) {
    return getOriginalResponseData(pending);
  }

  return pending.isBase64
    ? HttpModel.base64ToBytes(modifiedResponse.body)
    : new TextEncoder().encode(String(modifiedResponse.body ?? ""));
}

function writeOriginalResponseFailSafe(pending, context) {
  try {
    pending.filter.write(getOriginalResponseData(pending));
  } catch (error) {
    console.error(
      `Failed to restore original response after ${context}:`,
      error,
    );
  }

  try {
    pending.filter.close();
  } catch {}
}

function handleForwardResponse(requestId, modifiedResponse, port) {
  modifiedResponse =
    modifiedResponse && typeof modifiedResponse === "object"
      ? modifiedResponse
      : {};
  const headerIntercept = pendingResponseHeaderIntercepts.get(requestId);
  if (headerIntercept) {
    const { request } = headerIntercept;
    const validation = RequestInterception.validateEditedResponse(
      modifiedResponse,
      { maxBodyBytes: EDITABLE_RESPONSE_LIMIT },
    );
    if (!validation.valid) {
      sendResponseValidationError(port, requestId, validation.errors);
      return;
    }

    const sourceHeaders = modifiedResponse?.headersEdited
      ? modifiedResponse.headers
      : headerIntercept.responseHeaders;
    // Response body editing happens after headers are released. Content-Length
    // must therefore be removed up front so a later body edit cannot leave a
    // stale byte count on the wire.
    const forwardedHeaders = HttpModel.removeHeader(
      sourceHeaders,
      "content-length",
    );

    if (request) {
      request.responseHeaders = HttpModel.cloneHeaders(forwardedHeaders);
      if (modifiedResponse?.headersEdited) {
        request.statusLine = "Response Headers Modified";
      }
      notifyDevTools({ type: "updateRequest", request });
    }

    resolvePendingResponseHeaders(
      requestId,
      headerIntercept,
      { responseHeaders: forwardedHeaders },
      "headers-forwarded",
    );
    return;
  }

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
    const validation = RequestInterception.validateEditedResponse(
      modifiedResponse,
      { maxBodyBytes: EDITABLE_RESPONSE_LIMIT },
    );
    if (!validation.valid) {
      sendResponseValidationError(port, requestId, validation.errors);
      return;
    }

    let modifiedData;
    try {
      // Decode and size-check before settling the pending response. A bad edit
      // must leave the interception open so the user can correct it.
      modifiedData = prepareModifiedResponseData(pending, modifiedResponse);
    } catch (error) {
      sendResponseValidationError(port, requestId, [
        {
          field: "body",
          code: "invalid-body-encoding",
          message: `The edited response body could not be decoded: ${error.message}`,
        },
      ]);
      return;
    }

    settlePendingData(pending, () => {
      pendingResponses.delete(originalRequestId);

      try {
        const request = requests.get(requestId);
        if (request) {
          request.responseIntercepted = false;
          request.statusLine = modifiedResponse.bodyEdited
            ? "Response Body Modified"
            : "Response Forwarded";
          notifyDevTools({
            type: "updateRequest",
            request: request,
          });
        }

        pending.filter.write(modifiedData);
        pending.filter.close();
        notifyInterceptionReleased(pending, "response", "body-forwarded");
      } catch (e) {
        console.error("Failed to forward modified response:", e);
        writeOriginalResponseFailSafe(
          pending,
          "modified response write failure",
        );
        notifyInterceptionReleased(pending, "response", "body-forward-failed");
      }
    });
  }
}

function handleDropResponse(requestId) {
  const headerIntercept = pendingResponseHeaderIntercepts.get(requestId);
  if (headerIntercept) {
    const request = requests.get(requestId);
    if (request) {
      request.responseIntercepted = false;
      request.statusLine = "Response Dropped";
      request.statusCode = 0;
      request.completed = true;
      notifyDevTools({ type: "updateRequest", request });
    }

    resolvePendingResponseHeaders(
      requestId,
      headerIntercept,
      { cancel: true },
      "dropped",
    );
    interceptedRequestIds.delete(headerIntercept.originalRequestId);
    interceptedResponseTabIds.delete(headerIntercept.originalRequestId);
    responseInterceptionControls.delete(headerIntercept.originalRequestId);
    try {
      headerIntercept.filter?.close();
    } catch {}
    return;
  }

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
    settlePendingData(pending, () => {
      pendingResponses.delete(originalRequestId);
      const request = requests.get(requestId);
      if (request) {
        request.responseIntercepted = false;
        request.statusLine = "Response Dropped";
        request.statusCode = 0;
        request.completed = true;
        notifyDevTools({
          type: "updateRequest",
          request: request,
        });
      }

      pending.filter.close();
      notifyInterceptionReleased(pending, "response", "dropped");
    });
  }
}

function getOriginalResponseData(responseData) {
  if (responseData.originalBytes) {
    return responseData.originalBytes;
  }

  if (!responseData.isBase64) {
    return new TextEncoder().encode(responseData.responseBody);
  }

  return HttpModel.base64ToBytes(responseData.responseBody);
}

function releasePendingInterceptions(tabId = null) {
  const belongsToTab = (pendingData) =>
    tabId === null ||
    pendingData?.tabId === tabId ||
    pendingData?.request?.tabId === tabId;

  for (const [originalRequestId, pendingData] of pendingRequests.entries()) {
    if (belongsToTab(pendingData)) {
      resolvePendingRequest(
        originalRequestId,
        pendingData,
        pendingData.fallbackResponse || {},
        "disabled",
      );
    }
  }

  // Response interception starts by pausing at onHeadersReceived. These
  // Promises must be resolved separately; they are not stored in
  // pendingResponses until after the body arrives.
  for (const [
    requestId,
    pendingData,
  ] of pendingResponseHeaderIntercepts.entries()) {
    if (belongsToTab(pendingData)) {
      resolvePendingResponseHeaders(requestId, pendingData, {}, "disabled");
    }
  }

  for (const [originalRequestId, responseData] of pendingResponses.entries()) {
    if (!belongsToTab(responseData)) continue;

    settlePendingData(responseData, () => {
      pendingResponses.delete(originalRequestId);
      try {
        responseData.filter.write(getOriginalResponseData(responseData));
        responseData.filter.close();
      } catch (error) {
        console.error("Failed to release intercepted response:", error);
        try {
          responseData.filter.close();
        } catch {}
      }
      notifyInterceptionReleased(responseData, "response", "disabled");
    });
  }

  for (const originalRequestId of interceptedRequestIds) {
    const interceptedTabId = interceptedResponseTabIds.get(originalRequestId);
    if (tabId === null || interceptedTabId === tabId) {
      const responseControl =
        responseInterceptionControls.get(originalRequestId);
      if (responseControl) responseControl.bypassBody = true;
      interceptedRequestIds.delete(originalRequestId);
      interceptedResponseTabIds.delete(originalRequestId);
    }
  }
}

function handleDisableIntercept(tabId) {
  setTabInterceptEnabled(tabId, false);
}

function inferMessageTabId(message) {
  if (message.request?.tabId !== undefined) return message.request.tabId;
  if (message.finding?.tabId !== undefined) return message.finding.tabId;

  const responseRequestId = message.response?.requestId;
  if (responseRequestId && requests.has(responseRequestId)) {
    return requests.get(responseRequestId).tabId;
  }

  return null;
}

function notifyDevTools(message, explicitTabId) {
  const tabId =
    arguments.length > 1 ? explicitTabId : inferMessageTabId(message);
  const failures = devtoolsPorts.postMessage(message, tabId);

  for (const { error } of failures) {
    console.error("Failed to send message to devtools:", error);
  }
}

function applyRuleReplacement(source, rule) {
  return MatchReplace.applyRuleReplacement(source, rule);
}

async function readFetchResponsePrefix(response, limit) {
  const collector = ByteBufferCore.createBoundedCollector(limit);
  const reader = response.body?.getReader();
  const declaredLength = parseInt(response.headers.get("content-length"), 10);

  if (!reader) {
    if (Number.isFinite(declaredLength) && declaredLength > limit) {
      return {
        bytes: new Uint8Array(0),
        capturedBytes: 0,
        totalBytes: declaredLength,
        truncated: true,
      };
    }
    const bytes = new Uint8Array(await response.arrayBuffer());
    collector.add(bytes);
  } else {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      collector.add(value);
      if (collector.truncated) {
        await reader.cancel("display limit reached");
        break;
      }
    }
  }

  return {
    bytes: collector.toUint8Array(),
    capturedBytes: collector.capturedBytes,
    totalBytes:
      Number.isFinite(declaredLength) && declaredLength >= 0
        ? declaredLength
        : collector.totalBytes,
    truncated:
      collector.truncated ||
      (Number.isFinite(declaredLength) &&
        declaredLength > collector.capturedBytes),
  };
}

function createExtensionRequestId(source) {
  const randomValues = new Uint32Array(4);
  crypto.getRandomValues(randomValues);
  const randomPart = Array.from(randomValues, (value) =>
    value.toString(16).padStart(8, "0"),
  ).join("");
  return `${source}_${++extensionRequestCounter}_${Date.now()}_${randomPart}`;
}

function safePortMessage(port, message) {
  try {
    port?.postMessage(message);
    return true;
  } catch {
    return false;
  }
}

function extensionRequestErrorMessage(error, sourceLabel) {
  return error?.name === "AbortError"
    ? `${sourceLabel} request timed out after 30 seconds.`
    : error?.message || `${sourceLabel} request failed.`;
}

async function sendExtensionRequest(requestData, source) {
  const extensionRequestId = createExtensionRequestId(source);
  const controller = new AbortController();
  const timeoutId = setTimeout(
    () => controller.abort(),
    EXTENSION_REQUEST_TIMEOUT_MS,
  );

  try {
    let extensionHeaders = HttpModel.removeHeader(
      requestData.headers,
      EXTENSION_REQUEST_MARKER_HEADER,
    );
    if (requestData.body !== undefined) {
      extensionHeaders = HttpModel.removeHeader(
        extensionHeaders,
        "content-length",
      );
    }

    pendingExtensionRequests.set(extensionRequestId, {
      source,
      headers: extensionHeaders,
      url: requestData.url,
      method: requestData.method,
      body: requestData.body,
      createdAt: Date.now(),
    });

    const options = {
      method: requestData.method,
      headers: {
        [EXTENSION_REQUEST_MARKER_HEADER]: extensionRequestId,
      },
      redirect: "follow",
      signal: controller.signal,
    };

    if (
      HttpModel.requestMethodAllowsBody(requestData.method) &&
      requestData.body !== undefined
    ) {
      options.body =
        requestData.bodyEncoding === "base64"
          ? HttpModel.base64ToBytes(requestData.body)
          : requestData.body;
    }

    const startTime = Date.now();
    const response = await fetch(requestData.url, options);
    const duration = Date.now() - startTime;

    let responseHeaders = [];
    response.headers.forEach((value, key) => {
      responseHeaders.push({ name: key, value });
    });
    if (typeof response.headers.getSetCookie === "function") {
      const cookies = response.headers.getSetCookie();
      if (cookies.length > 0) {
        responseHeaders = HttpModel.removeHeader(responseHeaders, "set-cookie");
        responseHeaders.push(
          ...cookies.map((value) => ({ name: "set-cookie", value })),
        );
      }
    }

    const contentType = (
      HttpModel.getHeaderValue(responseHeaders, "content-type") || ""
    ).toLowerCase();
    const isTextResponse =
      contentType.startsWith("text/") ||
      contentType.includes("json") ||
      contentType.includes("xml") ||
      contentType.includes("javascript") ||
      contentType.includes("x-www-form-urlencoded");
    const responseCapture = await readFetchResponsePrefix(
      response,
      DISPLAY_CAPTURE_LIMIT,
    );
    const responseBytes = responseCapture.bytes;
    const responseBody = isTextResponse
      ? new TextDecoder("utf-8").decode(responseBytes)
      : HttpModel.bytesToBase64(responseBytes);

    return {
      status: response.status,
      statusText: response.statusText,
      headers: responseHeaders,
      body: responseBody,
      isBase64: !isTextResponse,
      capturedBytes: responseCapture.capturedBytes,
      totalBytes: responseCapture.totalBytes,
      truncated: responseCapture.truncated,
      duration,
      finalUrl: response.url,
      redirected: response.redirected,
      extensionOrigin: true,
      source,
    };
  } finally {
    clearTimeout(timeoutId);
    extensionRequestChains.clearExtension(extensionRequestId);
    pendingExtensionRequests.delete(extensionRequestId);
  }
}

async function handleRepeaterRequest(requestData, port, requestId) {
  try {
    const validation = RequestInterception.validateEditedRequest(requestData, {
      maxBodyBytes: EDITABLE_RESPONSE_LIMIT,
    });
    if (!validation.valid) {
      safePortMessage(port, {
        type: "repeaterError",
        requestId,
        error: validation.errors.map((item) => item.message).join(" "),
        validationErrors: validation.errors,
      });
      return;
    }

    const response = await sendExtensionRequest(requestData, "repeater");
    safePortMessage(port, { type: "repeaterResponse", requestId, response });
  } catch (error) {
    safePortMessage(port, {
      type: "repeaterError",
      requestId,
      error: extensionRequestErrorMessage(error, "Repeater"),
    });
  }
}
