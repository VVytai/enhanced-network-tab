const HttpModel = globalThis.EnhancedNetworkTab.HttpModelCore;
const RequestInterception =
    globalThis.EnhancedNetworkTab.RequestInterceptionCore;
const MatchReplace = globalThis.EnhancedNetworkTab.MatchReplaceCore;
const SecurityScanner = globalThis.EnhancedNetworkTab.SecurityScannerCore;
const harMatcher = globalThis.EnhancedNetworkTab.HarMatcherCore.createMatcher();
const port = browser.runtime.connect({ name: "devtools-panel" });
const inspectedTabId = browser.devtools.inspectedWindow.tabId;
let requests = [];
let selectedRequest = null;

// Send the inspected tab ID to background script
port.postMessage({ type: "setInspectedTab", tabId: inspectedTabId });
let currentRequestView = "raw";
let currentResponseView = "raw";
let currentModifiedView = "raw";
let currentTab = "request";
let interceptedRequest = null;
let interceptQueue = [];
let hiddenTypes = new Set();
let selectedMethods = new Set([
    "GET",
    "POST",
    "PUT",
    "DELETE",
    "PATCH",
    "OPTIONS",
    "HEAD",
]);
let selectedStatusGroups = new Set(["2xx", "3xx", "4xx", "5xx", "0"]);
const selectedDomains = new Set(); // Empty set means all domains implicitly allowed
let securityOnlyFilter = false;
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
let interceptedResponse = null;
let responseQueue = [];
let interceptHeadersEdited = false;
let interceptBodyEdited = false;
let responseHeadersEdited = false;
let responseBodyEdited = false;
let repeaterBodyEncoding = "text";
let repeaterBodyReplayable = true;
let activeReplacementRequestId = null;
let activeRepeaterRequestId = null;
let repeaterRequestCounter = 0;
let currentSortColumn = "number";
let currentSortDirection = "desc";
let requestCounter = 0;
let highlightRules = [];
let matchReplaceRules = [];
const MAX_REPLAY_BODY_BYTES = 10 * 1024 * 1024;

function sanitizeMatchReplaceRules(rules) {
    return MatchReplace.sanitizeRules(rules);
}

function significantFindingCount(finding) {
    return finding?.significantFindings ?? finding?.totalFindings ?? 0;
}

// Use devtools.network API to catch service worker responses that bypass webRequest API
let pendingHarEntries = []; // Buffer for HAR events that haven't matched yet

function updateRequestFromHar(request, harEntry) {
    const statusCode = harEntry.response?.status;
    const statusText = harEntry.response?.statusText || "";

    if (request.statusCode === null || request.statusCode === undefined) {
        request.statusCode = statusCode;
        request.statusLine = `HTTP/1.1 ${statusCode} ${statusText}`;
    }
    request.completed = true;

    // Extract request headers from HAR
    if (
        harEntry.request?.headers &&
        HttpModel.normalizeHeaders(request.requestHeaders).length === 0
    ) {
        request.requestHeaders = HttpModel.cloneHeaders(
            harEntry.request.headers,
        );
    }

    // Extract request body from HAR (for POST/PUT requests)
    if (harEntry.request?.postData && !request.requestBody) {
        request.requestBody = harEntry.request.postData.text || "";
        if (harEntry.request.postData.params && !request.requestBody) {
            // URL-encoded form data
            request.requestBody = harEntry.request.postData.params
                .map(
                    (p) =>
                        `${encodeURIComponent(p.name)}=${encodeURIComponent(p.value || "")}`,
                )
                .join("&");
        }
        request.requestBodyModel = {
            kind: "text",
            text: request.requestBody,
            byteLength: new TextEncoder().encode(request.requestBody)
                .byteLength,
            editable: true,
            replayable: true,
        };
    }

    // Extract request size
    if (harEntry.request?.bodySize > 0 && !request.requestSize) {
        request.requestSize = harEntry.request.bodySize;
    }

    // Extract response headers from HAR
    if (
        harEntry.response?.headers &&
        HttpModel.normalizeHeaders(request.responseHeaders).length === 0
    ) {
        request.responseHeaders = HttpModel.cloneHeaders(
            harEntry.response.headers,
        );
    }

    // Extract response size
    if (!request.responseSize && harEntry.response?.bodySize > 0) {
        request.responseSize = harEntry.response.bodySize;
    } else if (!request.responseSize && harEntry.response?.content?.size > 0) {
        request.responseSize = harEntry.response.content.size;
    }

    // Try to get response body from HAR content.text first (available in getHAR results)
    if (harEntry.response?.content?.text && !request.responseBody) {
        request.responseBody = harEntry.response.content.text;
    }

    // Try to get response body via getContent() if available (only works on event listener entries)
    if (typeof harEntry.getContent === "function" && !request.responseBody) {
        harEntry.getContent((content, encoding) => {
            if (content) {
                request.responseBody = content;
                // Re-render if this request is selected
                if (selectedRequest && selectedRequest.id === request.id) {
                    displayRequestDetails(request);
                }
            }
        });
    }
}

function tryMatchHarEntry(harEntry) {
    if (harMatcher.isProcessed(harEntry)) return true;
    const request = harMatcher.match(harEntry, requests);
    if (!request) return false;

    request.harFingerprint = harMatcher.fingerprint(harEntry);
    updateRequestFromHar(request, harEntry);
    return true;
}

function processPendingHarEntries() {
    if (pendingHarEntries.length === 0) return;

    const stillPending = [];
    let matched = false;
    for (const harEntry of pendingHarEntries) {
        if (tryMatchHarEntry(harEntry)) {
            matched = true;
        } else {
            // Keep entries that are less than 5 seconds old
            if (Date.now() - harEntry._timestamp < 5000) {
                stillPending.push(harEntry);
            }
        }
    }
    pendingHarEntries = stillPending;

    if (matched) {
        renderRequestList();
    }
}

if (browser.devtools && browser.devtools.network) {
    // Listen for request completions from devtools.network API
    browser.devtools.network.onRequestFinished.addListener((harEntry) => {
        const url = harEntry.request?.url;
        const statusCode = harEntry.response?.status;

        if (!url || statusCode === undefined) return;

        // Try to match immediately
        if (!tryMatchHarEntry(harEntry)) {
            // Buffer for later matching (request might not be in our list yet)
            harEntry._timestamp = Date.now();
            pendingHarEntries = pendingHarEntries
                .filter((entry) => Date.now() - entry._timestamp < 5000)
                .slice(-499);
            pendingHarEntries.push(harEntry);
        }

        renderRequestList();
        if (selectedRequest) {
            const updated = requests.find((r) => r.id === selectedRequest.id);
            if (updated) displayRequestDetails(updated);
        }
    });
}

// Security Scanner State
let securityFindings = []; // All findings from all requests
let libraryFindings = []; // Vulnerable library findings
let unseenFindingsCount = 0; // Number of unseen findings (for badge)
const requestFindings = new Map(); // Map of requestId -> findings
const requestLibraryFindings = new Map(); // Map of requestId -> library findings

// Theme Management
let currentTheme = "auto"; // 'auto', 'light', or 'dark'
const browserPrefersDark = window.matchMedia("(prefers-color-scheme: dark)");

// Column Resizing
let isResizing = false;
let currentResizer = null;
let currentColumn = null;
let startX = 0;
let startWidth = 0;

// Default column widths (in pixels)
const defaultColumnWidths = {
    number: 60,
    method: 100,
    host: 200,
    url: 250,
    status: 90,
    reqSize: 100,
    resSize: 100,
    type: 100,
};

// Minimum column widths (in pixels)
const minColumnWidths = {
    number: 40,
    method: 80,
    host: 120,
    url: 150,
    status: 70,
    reqSize: 80,
    resSize: 80,
    type: 80,
};

// Initialize theme and column resizing on load
initializeTheme();
initializeColumnResizing();

function initializeTheme() {
    // Load saved theme preference
    browser.storage.local
        .get("theme")
        .then((result) => {
            if (result.theme) {
                currentTheme = result.theme;
            }
            applyTheme();
            updateThemeButton();
        })
        .catch(() => {
            // If storage fails, use default
            applyTheme();
            updateThemeButton();
        });

    // Listen for browser theme changes (only when in auto mode)
    browserPrefersDark.addEventListener("change", (e) => {
        if (currentTheme === "auto") {
            applyTheme();
        }
    });
}

function applyTheme() {
    const shouldUseDarkMode =
        currentTheme === "dark" ||
        (currentTheme === "auto" && browserPrefersDark.matches);

    if (shouldUseDarkMode) {
        document.body.classList.add("dark-mode");
    } else {
        document.body.classList.remove("dark-mode");
    }
}

function updateThemeButton() {
    const themeBtn = document.getElementById("themeToggleBtn");
    const themeIcon = themeBtn.querySelector(".theme-icon");

    // Update icon based on current theme
    if (currentTheme === "auto") {
        themeIcon.textContent = "🔄";
        themeBtn.title = "Theme: Auto (following browser)";
    } else if (currentTheme === "light") {
        themeIcon.textContent = "☀️";
        themeBtn.title = "Theme: Light";
    } else {
        themeIcon.textContent = "🌙";
        themeBtn.title = "Theme: Dark";
    }
}

function toggleTheme() {
    // Cycle through: auto → light → dark → auto
    if (currentTheme === "auto") {
        currentTheme = "light";
    } else if (currentTheme === "light") {
        currentTheme = "dark";
    } else {
        currentTheme = "auto";
    }

    // Save preference
    browser.storage.local.set({ theme: currentTheme }).catch((err) => {
        console.error("Failed to save theme preference:", err);
    });

    applyTheme();
    updateThemeButton();
}

// Column Resizing Functions
function initializeColumnResizing() {
    // Load saved column widths
    applyColumnWidths();

    // Load highlight rules
    const savedRules = localStorage.getItem("highlightRules");
    if (savedRules) {
        try {
            highlightRules = JSON.parse(savedRules);
        } catch (e) {
            console.error("Failed to parse highlight rules:", e);
        }
    }

    // Load Match & Replace rules
    const savedMRRules = localStorage.getItem("matchReplaceRules");
    if (savedMRRules) {
        try {
            matchReplaceRules = sanitizeMatchReplaceRules(
                JSON.parse(savedMRRules),
            );
            localStorage.setItem(
                "matchReplaceRules",
                JSON.stringify(matchReplaceRules),
            );
            // Sync with background
            port.postMessage({
                type: "updateMatchReplaceRules",
                rules: matchReplaceRules,
            });
        } catch (e) {
            console.error("Failed to parse match & replace rules:", e);
        }
    }

    // Get all column resizers
    const resizers = document.querySelectorAll(".column-resizer");

    resizers.forEach((resizer) => {
        // Mouse down on resizer
        resizer.addEventListener("mousedown", (e) => {
            e.preventDefault();
            e.stopPropagation();

            isResizing = true;
            currentResizer = resizer;
            currentColumn = resizer.parentElement;
            startX = e.pageX;
            startWidth = currentColumn.offsetWidth;

            document.body.classList.add("column-resizing");
        });

        // Double-click to auto-fit
        resizer.addEventListener("dblclick", (e) => {
            e.preventDefault();
            e.stopPropagation();

            const th = resizer.parentElement;
            const columnName = th.dataset.column;
            autoFitColumn(columnName);
        });
    });

    // Mouse move - resize column
    document.addEventListener("mousemove", (e) => {
        if (!isResizing) return;

        const width = startWidth + (e.pageX - startX);
        const columnName = currentColumn.dataset.column;
        const minWidth = minColumnWidths[columnName] || 50;

        if (width >= minWidth) {
            currentColumn.style.width = width + "px";
        }
    });

    // Mouse up - stop resizing
    document.addEventListener("mouseup", () => {
        if (isResizing) {
            isResizing = false;
            document.body.classList.remove("column-resizing");

            // Save the new widths
            saveColumnWidths();

            currentResizer = null;
            currentColumn = null;
        }
    });
}

function applyColumnWidths() {
    const savedWidths = localStorage.getItem("columnWidths");
    let widths = defaultColumnWidths;

    if (savedWidths) {
        try {
            widths = JSON.parse(savedWidths);
        } catch (e) {
            console.error("Failed to parse saved column widths:", e);
        }
    }

    // Apply widths to all columns
    Object.keys(widths).forEach((columnName) => {
        const th = document.querySelector(`th[data-column="${columnName}"]`);
        if (th) {
            th.style.width = widths[columnName] + "px";
        }
    });
}

function saveColumnWidths() {
    const widths = {};
    const headers = document.querySelectorAll("#requestTable th[data-column]");

    headers.forEach((th) => {
        const columnName = th.dataset.column;
        widths[columnName] = th.offsetWidth;
    });

    localStorage.setItem("columnWidths", JSON.stringify(widths));
}

function autoFitColumn(columnName) {
    const th = document.querySelector(`th[data-column="${columnName}"]`);
    if (!th) return;

    // Get all cells in this column
    const columnIndex = Array.from(th.parentElement.children).indexOf(th);
    const cells = document.querySelectorAll(
        `#requestTable tr td:nth-child(${columnIndex + 1})`,
    );

    // Calculate maximum content width
    let maxWidth = minColumnWidths[columnName] || 50;

    // Measure header text
    const headerText = th.textContent.replace("▲", "").replace("▼", "").trim();
    const headerWidth =
        measureTextWidth(
            headerText,
            '12px -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen, Ubuntu, sans-serif',
        ) + 30; // Add padding
    maxWidth = Math.max(maxWidth, headerWidth);

    // Measure visible cell content
    cells.forEach((cell) => {
        const text = cell.textContent;
        const width =
            measureTextWidth(
                text,
                '12px -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen, Ubuntu, sans-serif',
            ) + 20; // Add padding
        maxWidth = Math.max(maxWidth, width);
    });

    // Cap at reasonable maximum
    maxWidth = Math.min(maxWidth, 500);

    // Apply the width
    th.style.width = maxWidth + "px";

    // Save the new widths
    saveColumnWidths();
}

function measureTextWidth(text, font) {
    const canvas =
        measureTextWidth.canvas ||
        (measureTextWidth.canvas = document.createElement("canvas"));
    const context = canvas.getContext("2d");
    context.font = font;
    const metrics = context.measureText(text);
    return metrics.width;
}

const captureToggle = document.getElementById("captureToggle");
const interceptToggle = document.getElementById("interceptToggle");
const clearBtn = document.getElementById("clearBtn");
const filterBtn = document.getElementById("filterBtn");
const filterPanel = document.getElementById("filterPanel");
const searchInput = document.getElementById("searchInput");
const requestList = document.getElementById("requestList");
const requestContent = document.getElementById("requestContent");
const modifiedContent = document.getElementById("modifiedContent");
const responseContent = document.getElementById("responseContent");
const interceptModal = document.getElementById("interceptModal");
const copyCurlBtn = document.getElementById("copyCurlBtn");
const repeaterBtn = document.getElementById("repeaterBtn");
const repeaterModal = document.getElementById("repeaterModal");
const closeRepeaterBtn = document.getElementById("closeRepeaterBtn");
const sendRepeaterBtn = document.getElementById("sendRepeaterBtn");
const clearRepeaterBtn = document.getElementById("clearRepeaterBtn");
const interceptSettingsBtn = document.getElementById("interceptSettingsBtn");
const interceptSettingsModal = document.getElementById(
    "interceptSettingsModal",
);
const closeInterceptSettingsBtn = document.getElementById(
    "closeInterceptSettingsBtn",
);
const saveInterceptSettingsBtn = document.getElementById(
    "saveInterceptSettingsBtn",
);
const resetInterceptSettingsBtn = document.getElementById(
    "resetInterceptSettingsBtn",
);
const experimentalPromotionBanner = document.getElementById(
    "experimentalPromotionBanner",
);
const openExperimentalSettingsBtn = document.getElementById(
    "openExperimentalSettingsBtn",
);
const dismissExperimentalPromotionBtn = document.getElementById(
    "dismissExperimentalPromotionBtn",
);
const modifiedRequestActionSection = document.getElementById(
    "modifiedRequestActionSection",
);
const responseInterceptModal = document.getElementById(
    "responseInterceptModal",
);
const forwardResponseBtn = document.getElementById("forwardResponseBtn");
const dropResponseBtn = document.getElementById("dropResponseBtn");
const disableInterceptBtn = document.getElementById("disableInterceptBtn");
const disableInterceptResponseBtn = document.getElementById(
    "disableInterceptResponseBtn",
);
const requestSearchInput = document.getElementById("requestSearchInput");
const modifiedSearchInput = document.getElementById("modifiedSearchInput");
const responseSearchInput = document.getElementById("responseSearchInput");
const requestSearchCount = document.getElementById("requestSearchCount");
const modifiedSearchCount = document.getElementById("modifiedSearchCount");
const responseSearchCount = document.getElementById("responseSearchCount");
const themeToggleBtn = document.getElementById("themeToggleBtn");
const copyRequestBtn = document.getElementById("copyRequestBtn");
const copyResponseBtn = document.getElementById("copyResponseBtn");
const responsePreviewBtn = document.getElementById("responsePreviewBtn");
const highlightRulesBtn = document.getElementById("highlightRulesBtn");
const highlightRulesModal = document.getElementById("highlightRulesModal");
const closeHighlightRulesBtn = document.getElementById(
    "closeHighlightRulesBtn",
);
const addHighlightRuleBtn = document.getElementById("addHighlightRuleBtn");
const saveHighlightRulesBtn = document.getElementById("saveHighlightRulesBtn");
const clearHighlightRulesBtn = document.getElementById(
    "clearHighlightRulesBtn",
);
const highlightRulesList = document.getElementById("highlightRulesList");

const matchReplaceBtn = document.getElementById("matchReplaceBtn");
const matchReplaceModal = document.getElementById("matchReplaceModal");
const closeMatchReplaceBtn = document.getElementById("closeMatchReplaceBtn");
const addMatchReplaceRuleBtn = document.getElementById(
    "addMatchReplaceRuleBtn",
);
const saveMatchReplaceRulesBtn = document.getElementById(
    "saveMatchReplaceRulesBtn",
);
const clearMatchReplaceRulesBtn = document.getElementById(
    "clearMatchReplaceRulesBtn",
);
const matchReplaceRulesList = document.getElementById("matchReplaceRulesList");
const mrTarget = document.getElementById("mrTarget");
const mrHeaderNameRow = document.getElementById("mrHeaderNameRow");
const mrHeaderName = document.getElementById("mrHeaderName");
const mrMatchPattern = document.getElementById("mrMatchPattern");
const mrMatchPatternLabel = document.getElementById("mrMatchPatternLabel");

// Security Scanner Elements
const securityBtn = document.getElementById("securityBtn");
const securityBadge = document.getElementById("securityBadge");
const securityModal = document.getElementById("securityModal");
const closeSecurityBtn = document.getElementById("closeSecurityBtn");
const securityFindingsList = document.getElementById("securityFindingsList");
const securitySearchInput = document.getElementById("securitySearchInput");
const securityCategoryFilter = document.getElementById(
    "securityCategoryFilter",
);
const securitySeverityFilter = document.getElementById(
    "securitySeverityFilter",
);
const securityDomainFilter = document.getElementById("securityDomainFilter");
const securityRefererFilter = document.getElementById("securityRefererFilter");
const clearSecurityFindingsBtn = document.getElementById(
    "clearSecurityFindingsBtn",
);
const exportAllSecurityBtn = document.getElementById("exportAllSecurityBtn");
const securityTabBtn = document.getElementById("securityTabBtn");
const securityTabBadge = document.getElementById("securityTabBadge");
const securityTabContent = document.getElementById("securityTabContent");
const exportSecurityFindingsBtn = document.getElementById(
    "exportSecurityFindingsBtn",
);
const updateVulnerabilityDbBtn = document.getElementById(
    "updateVulnerabilityDbBtn",
);
const autoUpdateVulnerabilityDb = document.getElementById(
    "autoUpdateVulnerabilityDb",
);
const vulnerabilityDbStatus = document.getElementById("vulnerabilityDbStatus");

// Filter Panel Expanded Elements
const filterSecurityOnly = document.getElementById("filter-security-only");
const activeFilterBadge = document.getElementById("activeFilterBadge");
const resetAllFiltersBtn = document.getElementById("resetAllFiltersBtn");
const domainSearchInput = document.getElementById("domainSearchInput");
const domainFilterList = document.getElementById("domainFilterList");
const domainSelectAllBtn = document.getElementById("domainSelectAllBtn");
const domainClearAllBtn = document.getElementById("domainClearAllBtn");

let currentRepeaterTab = "headers";
let lastRepeaterResponse = null;

// Highlight Rules Event Listeners
highlightRulesBtn.addEventListener("click", () => {
    renderHighlightRules();
    highlightRulesModal.classList.add("show");
});

closeHighlightRulesBtn.addEventListener("click", () => {
    highlightRulesModal.classList.remove("show");
});

addHighlightRuleBtn.addEventListener("click", () => {
    const pattern = document.getElementById("newRulePattern").value.trim();
    const color = document.getElementById("newRuleColor").value;
    const type = document.getElementById("newRuleType").value;

    if (!pattern) {
        alert("Please enter a pattern");
        return;
    }

    if (type === "regex") {
        try {
            new RegExp(pattern);
        } catch (e) {
            alert("Invalid regex pattern: " + e.message);
            return;
        }
    }

    highlightRules.push({ pattern, color, type, enabled: true });
    document.getElementById("newRulePattern").value = "";
    renderHighlightRules();
    saveHighlightRules();
});

// Match & Replace Event Listeners
matchReplaceBtn.addEventListener("click", () => {
    renderMatchReplaceRules();
    updateMatchReplaceForm();
    matchReplaceModal.classList.add("show");
});

closeMatchReplaceBtn.addEventListener("click", () => {
    matchReplaceModal.classList.remove("show");
});

mrTarget.addEventListener("change", updateMatchReplaceForm);

function updateMatchReplaceForm() {
    const targetsHeaders = mrTarget.value === "headers";
    mrHeaderNameRow.hidden = !targetsHeaders;
    mrMatchPatternLabel.textContent = targetsHeaders
        ? "Value Match:"
        : "Match Pattern:";
    mrMatchPattern.placeholder = targetsHeaders
        ? "e.g. original-value"
        : "e.g. https://api.prod.com";
}

addMatchReplaceRuleBtn.addEventListener("click", () => {
    const matchPattern = mrMatchPattern.value.trim();
    const replaceValue = document.getElementById("mrReplaceValue").value;
    const target = mrTarget.value;
    const matchType = document.getElementById("mrMatchType").value;
    const headerName = target === "headers" ? mrHeaderName.value.trim() : "";

    if (!matchPattern) {
        alert("Please enter a match pattern");
        return;
    }

    if (target === "headers" && !MatchReplace.isValidHeaderName(headerName)) {
        alert("Please enter a valid header name, for example x-test-header");
        mrHeaderName.focus();
        return;
    }

    if (matchType === "regex") {
        try {
            new RegExp(matchPattern);
        } catch (e) {
            alert("Invalid regex pattern: " + e.message);
            return;
        }
    }

    matchReplaceRules.push({
        matchPattern,
        replaceValue,
        target,
        matchType,
        ...(target === "headers" ? { headerName } : {}),
        enabled: true,
        id: Date.now().toString(),
    });

    // Clear form
    mrMatchPattern.value = "";
    document.getElementById("mrReplaceValue").value = "";

    renderMatchReplaceRules();
});

saveMatchReplaceRulesBtn.addEventListener("click", () => {
    saveMatchReplaceRules();
    matchReplaceModal.classList.remove("show");
});

clearMatchReplaceRulesBtn.addEventListener("click", () => {
    if (clearMatchReplaceRulesBtn.textContent === "Confirm?") {
        matchReplaceRules = [];
        renderMatchReplaceRules();
        saveMatchReplaceRules();
        clearMatchReplaceRulesBtn.textContent = "Clear All";
        clearMatchReplaceRulesBtn.classList.remove("confirm-state");
    } else {
        const originalText = clearMatchReplaceRulesBtn.textContent;
        clearMatchReplaceRulesBtn.textContent = "Confirm?";
        clearMatchReplaceRulesBtn.classList.add("confirm-state");

        setTimeout(() => {
            if (clearMatchReplaceRulesBtn.textContent === "Confirm?") {
                clearMatchReplaceRulesBtn.textContent = originalText;
                clearMatchReplaceRulesBtn.classList.remove("confirm-state");
            }
        }, 3000);
    }
});

function renderMatchReplaceRules() {
    matchReplaceRulesList.replaceChildren();

    if (matchReplaceRules.length === 0) {
        const emptyState = document.createElement("div");
        emptyState.style.padding = "10px";
        emptyState.style.color = "#888";
        emptyState.textContent = "No rules defined";
        matchReplaceRulesList.appendChild(emptyState);
        return;
    }

    matchReplaceRules.forEach((rule, index) => {
        const item = document.createElement("div");
        item.className = "rule-item";
        item.style.flexDirection = "column";
        item.style.alignItems = "flex-start";

        const header = document.createElement("div");
        header.style.display = "flex";
        header.style.width = "100%";
        header.style.justifyContent = "space-between";
        header.style.marginBottom = "5px";

        const title = document.createElement("span");
        const typeLabel = rule.matchType ? `[${rule.matchType}] ` : "[regex] ";
        const targetLabel =
            typeof rule.target === "string"
                ? rule.target.replace(/_/g, " ").toUpperCase()
                : "UNKNOWN";
        const target = document.createElement("strong");
        target.textContent = targetLabel;
        const type = document.createElement("small");
        type.textContent = typeLabel;
        const match = document.createElement("code");
        match.textContent = String(rule.matchPattern ?? "");
        const replacement = document.createElement("code");
        replacement.textContent = String(rule.replaceValue ?? "");
        title.append(target, document.createTextNode(": "));
        if (rule.target === "headers") {
            const headerName = document.createElement("code");
            headerName.textContent = rule.headerName || "<any header>";
            title.append(
                headerName,
                document.createTextNode(" value "),
                type,
                match,
                document.createTextNode(" → "),
                replacement,
            );
        } else {
            title.append(
                type,
                match,
                document.createTextNode(" → "),
                replacement,
            );
        }
        if (rule.disabledReason === "request-body-unsupported") {
            title.appendChild(
                document.createTextNode(" (disabled: use Repeater)"),
            );
        }

        const controls = document.createElement("div");

        const toggleCheck = document.createElement("input");
        toggleCheck.type = "checkbox";
        toggleCheck.checked = rule.enabled;
        toggleCheck.disabled =
            rule.disabledReason === "request-body-unsupported";
        toggleCheck.style.marginRight = "10px";
        toggleCheck.addEventListener("change", () => {
            rule.enabled = toggleCheck.checked;
            saveMatchReplaceRules();
        });

        const deleteBtn = document.createElement("button");
        deleteBtn.className = "rule-delete-btn";
        deleteBtn.textContent = "×";
        deleteBtn.addEventListener("click", () => {
            matchReplaceRules.splice(index, 1);
            renderMatchReplaceRules();
        });

        controls.appendChild(toggleCheck);
        controls.appendChild(deleteBtn);

        header.appendChild(title);
        header.appendChild(controls);

        item.appendChild(header);
        matchReplaceRulesList.appendChild(item);
    });
}

function saveMatchReplaceRules() {
    matchReplaceRules = sanitizeMatchReplaceRules(matchReplaceRules);
    localStorage.setItem(
        "matchReplaceRules",
        JSON.stringify(matchReplaceRules),
    );
    port.postMessage({
        type: "updateMatchReplaceRules",
        rules: matchReplaceRules,
    });
}

saveHighlightRulesBtn.addEventListener("click", () => {
    saveHighlightRules();
    highlightRulesModal.classList.remove("show");
    renderRequestList();
});

clearHighlightRulesBtn.addEventListener("click", () => {
    if (clearHighlightRulesBtn.textContent === "Confirm?") {
        highlightRules = [];
        renderHighlightRules();
        saveHighlightRules();
        renderRequestList();
        clearHighlightRulesBtn.textContent = "Clear All";
        clearHighlightRulesBtn.classList.remove("confirm-state");
    } else {
        const originalText = clearHighlightRulesBtn.textContent;
        clearHighlightRulesBtn.textContent = "Confirm?";
        clearHighlightRulesBtn.classList.add("confirm-state");

        setTimeout(() => {
            if (clearHighlightRulesBtn.textContent === "Confirm?") {
                clearHighlightRulesBtn.textContent = originalText;
                clearHighlightRulesBtn.classList.remove("confirm-state");
            }
        }, 3000);
    }
});

function renderHighlightRules() {
    highlightRulesList.replaceChildren();

    if (highlightRules.length === 0) {
        const emptyState = document.createElement("div");
        emptyState.style.padding = "10px";
        emptyState.style.color = "#888";
        emptyState.textContent = "No rules defined";
        highlightRulesList.appendChild(emptyState);
        return;
    }

    highlightRules.forEach((rule, index) => {
        const item = document.createElement("div");
        item.className = "rule-item";

        const colorPreview = document.createElement("div");
        colorPreview.className = "rule-color-preview";
        colorPreview.style.backgroundColor = rule.color;

        const patternText = document.createElement("span");
        patternText.className = "rule-pattern";
        const typeLabel = rule.type ? `[${rule.type}] ` : "[regex] ";
        patternText.textContent = typeLabel + rule.pattern;

        const deleteBtn = document.createElement("button");
        deleteBtn.className = "rule-delete-btn";
        deleteBtn.textContent = "×";
        deleteBtn.addEventListener("click", () => {
            highlightRules.splice(index, 1);
            renderHighlightRules();
            saveHighlightRules();
        });

        item.appendChild(colorPreview);
        item.appendChild(patternText);
        item.appendChild(deleteBtn);

        highlightRulesList.appendChild(item);
    });
}

function saveHighlightRules() {
    localStorage.setItem("highlightRules", JSON.stringify(highlightRules));
}

// ==========================================
// SECURITY SCANNER EVENT LISTENERS
// ==========================================

function renderVulnerabilityDbStatus(status) {
    if (!status) return;

    updateVulnerabilityDbBtn.disabled = false;
    vulnerabilityDbStatus.classList.remove("error", "success");

    if (status.error) {
        vulnerabilityDbStatus.textContent = `Update failed: ${status.error}`;
        vulnerabilityDbStatus.classList.add("error");
        return;
    }

    const source = status.source === "downloaded" ? "Downloaded" : "Bundled";
    const when = status.fetchedAt
        ? new Date(status.fetchedAt).toLocaleString()
        : "shipped copy";
    const libraries = status.libraries
        ? ` · ${status.libraries} libraries`
        : "";

    vulnerabilityDbStatus.textContent = status.refreshed
        ? `Updated: ${when}${libraries}`
        : `${source}: ${when}${libraries}`;
    if (status.refreshed) vulnerabilityDbStatus.classList.add("success");
}

function requestVulnerabilityDbStatus() {
    port.postMessage({ type: "getVulnerabilityDbStatus" });
}

// Off by default: the packaged database is used until the user opts in.
browser.storage.local
    .get("vulnerabilityDbAutoUpdate")
    .then((result) => {
        autoUpdateVulnerabilityDb.checked =
            result.vulnerabilityDbAutoUpdate === true;
    })
    .catch((err) => {
        console.error("Failed to load vulnerability database setting:", err);
    });

updateVulnerabilityDbBtn.addEventListener("click", () => {
    updateVulnerabilityDbBtn.disabled = true;
    vulnerabilityDbStatus.classList.remove("error", "success");
    vulnerabilityDbStatus.textContent = "Updating…";
    port.postMessage({ type: "updateVulnerabilityDb", force: true });
});

autoUpdateVulnerabilityDb.addEventListener("change", () => {
    const enabled = autoUpdateVulnerabilityDb.checked;
    browser.storage.local
        .set({ vulnerabilityDbAutoUpdate: enabled })
        .catch((err) => {
            console.error(
                "Failed to save vulnerability database setting:",
                err,
            );
        });
    if (enabled) {
        updateVulnerabilityDbBtn.disabled = true;
        vulnerabilityDbStatus.textContent = "Checking…";
        port.postMessage({ type: "updateVulnerabilityDb", force: false });
    }
});

// Open Security Modal
securityBtn.addEventListener("click", () => {
    // Mark all findings as seen
    unseenFindingsCount = 0;
    updateSecurityBadge();

    // Render and show modal
    renderSecurityModal();
    securityModal.classList.add("show");
    requestVulnerabilityDbStatus();
});

// Close Security Modal
closeSecurityBtn.addEventListener("click", () => {
    securityModal.classList.remove("show");
});

// Security Search
securitySearchInput.addEventListener("input", () => {
    renderSecurityFindingsList();
});

// Security Category Filter
securityCategoryFilter.addEventListener("change", () => {
    updateActiveSummaryChips();
    renderSecurityFindingsList();
});

// Security Severity Filter
securitySeverityFilter.addEventListener("change", () => {
    renderSecurityFindingsList();
});

// Security Domain Filter
if (securityDomainFilter) {
    securityDomainFilter.addEventListener("change", () => {
        renderSecurityFindingsList();
    });
}

// Security Referer Filter
if (securityRefererFilter) {
    securityRefererFilter.addEventListener("change", () => {
        renderSecurityFindingsList();
    });
}

// Interactive Summary Chips (Quick Filtering)
document.addEventListener("click", (e) => {
    const chip = e.target.closest(
        "#securitySummary .summary-item[data-category]",
    );
    if (!chip) return;
    const category = chip.dataset.category;
    if (securityCategoryFilter.value === category) {
        securityCategoryFilter.value = "all";
    } else {
        securityCategoryFilter.value = category;
    }
    updateActiveSummaryChips();
    renderSecurityFindingsList();
});

function updateActiveSummaryChips() {
    const activeCat = securityCategoryFilter.value;
    document
        .querySelectorAll("#securitySummary .summary-item[data-category]")
        .forEach((chip) => {
            if (chip.dataset.category === activeCat) {
                chip.classList.add("active");
            } else {
                chip.classList.remove("active");
            }
        });
}

// Clear All Security Findings
clearSecurityFindingsBtn.addEventListener("click", () => {
    if (clearSecurityFindingsBtn.textContent === "Confirm?") {
        securityFindings = [];
        libraryFindings = [];
        requestFindings.clear();
        requestLibraryFindings.clear();
        unseenFindingsCount = 0;

        // Reset security flags on all existing captured requests to prevent re-scanning
        requests.forEach((req) => {
            req.hasSecurityFindings = false;
            req.securityFindingsCount = 0;
            req.clearedSecurity = true;
        });

        updateSecurityBadge();
        renderSecurityModal();
        renderRequestList(); // Update request list to remove security indicators
        clearSecurityFindingsBtn.textContent = "Clear All";
        clearSecurityFindingsBtn.classList.remove("confirm-state");
        // Also notify background to clear
        port.postMessage({ type: "clearSecurityFindings" });
        port.postMessage({ type: "clearLibraryFindings" });
    } else {
        clearSecurityFindingsBtn.textContent = "Confirm?";
        clearSecurityFindingsBtn.classList.add("confirm-state");

        setTimeout(() => {
            if (clearSecurityFindingsBtn.textContent === "Confirm?") {
                clearSecurityFindingsBtn.textContent = "Clear All";
                clearSecurityFindingsBtn.classList.remove("confirm-state");
            }
        }, 3000);
    }
});

// Export All Security Findings
exportAllSecurityBtn.addEventListener("click", () => {
    const allFindings = {
        securityFindings: securityFindings,
        libraryFindings: libraryFindings,
        exportedAt: new Date().toISOString(),
    };
    const blob = new Blob([JSON.stringify(allFindings, null, 2)], {
        type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "all-security-findings.json";
    a.click();
    URL.revokeObjectURL(url);
});

// Export Security Findings for Selected Request
exportSecurityFindingsBtn.addEventListener("click", () => {
    if (selectedRequest && requestFindings.has(selectedRequest.id)) {
        const findings = requestFindings.get(selectedRequest.id);
        exportSecurityFindings(
            [findings],
            `security-findings-${selectedRequest.id}.json`,
        );
    }
});

/**
 * Update the security badge count
 */
function updateSecurityBadge() {
    if (unseenFindingsCount > 0) {
        securityBadge.textContent =
            unseenFindingsCount > 99 ? "99+" : unseenFindingsCount;
        securityBadge.style.display = "flex";
    } else {
        securityBadge.style.display = "none";
    }
}

/**
 * Render the security modal with all findings
 */
function renderSecurityModal() {
    // Update summary counts
    let apiKeyCount = 0,
        credentialCount = 0,
        emailCount = 0,
        endpointCount = 0,
        pathCount = 0,
        libraryCount = 0;

    // Track unique domains and referers for filter dropdowns
    const domains = new Set();
    const referers = new Set();

    const addMeta = (f) => {
        let d = f.domain;
        if (!d && f.url) {
            try {
                d = new URL(f.url).hostname;
            } catch {}
        }
        if (d) domains.add(d);

        let r = f.refererDomain;
        if (!r && f.referer) {
            try {
                r = new URL(f.referer).hostname;
            } catch {}
        }
        if (r) referers.add(r);
    };

    securityFindings.forEach((finding) => {
        apiKeyCount += (finding.apiKeys || []).length;
        credentialCount += (finding.credentials || []).length;
        emailCount += (finding.emails || []).length;
        endpointCount += (finding.apiEndpoints || []).length;
        pathCount += (finding.paths || []).length;
        addMeta(finding);
    });

    // Count unique vulnerable library+version combinations
    const uniqueLibs = new Set();
    libraryFindings.forEach((finding) => {
        (finding.libraries || []).forEach((lib) => {
            uniqueLibs.add(`${lib.library}@${lib.version}`);
        });
        addMeta(finding);
    });
    libraryCount = uniqueLibs.size;

    document.getElementById("summaryApiKeys").textContent = apiKeyCount;
    document.getElementById("summaryCredentials").textContent = credentialCount;
    document.getElementById("summaryLibraries").textContent = libraryCount;
    document.getElementById("summaryEmails").textContent = emailCount;
    document.getElementById("summaryEndpoints").textContent = endpointCount;
    document.getElementById("summaryPaths").textContent = pathCount;

    // Update modal badge
    const totalSignificant = apiKeyCount + credentialCount + libraryCount;
    document.getElementById("securityModalBadge").textContent =
        totalSignificant;

    // Populate Domain Filter Options
    if (securityDomainFilter) {
        const selectedDom = securityDomainFilter.value;
        securityDomainFilter.innerHTML =
            '<option value="all">All Target Domains</option>';
        Array.from(domains)
            .sort()
            .forEach((d) => {
                const opt = document.createElement("option");
                opt.value = d;
                opt.textContent = d;
                if (d === selectedDom) opt.selected = true;
                securityDomainFilter.appendChild(opt);
            });
    }

    // Populate Referer Filter Options
    if (securityRefererFilter) {
        const selectedRef = securityRefererFilter.value;
        securityRefererFilter.innerHTML =
            '<option value="all">All Referer Origins</option>';
        Array.from(referers)
            .sort()
            .forEach((r) => {
                const opt = document.createElement("option");
                opt.value = r;
                opt.textContent = r;
                if (r === selectedRef) opt.selected = true;
                securityRefererFilter.appendChild(opt);
            });
    }

    updateActiveSummaryChips();

    // Render the findings list
    renderSecurityFindingsList();
}

/**
 * Render the security findings list with filters
 */
function renderSecurityFindingsList() {
    const searchTerm = securitySearchInput.value.toLowerCase();
    const categoryFilter = securityCategoryFilter.value;
    const severityFilter = securitySeverityFilter.value;
    const domainFilter = securityDomainFilter
        ? securityDomainFilter.value
        : "all";
    const refererFilter = securityRefererFilter
        ? securityRefererFilter.value
        : "all";

    securityFindingsList.innerHTML = "";

    const hasSecurityFindings = securityFindings.length > 0;
    const hasLibraryFindings = libraryFindings.length > 0;

    if (!hasSecurityFindings && !hasLibraryFindings) {
        securityFindingsList.innerHTML = `
            <div class="security-no-findings">
                <p>No security findings yet. Start browsing with capture enabled to scan response bodies.</p>
            </div>
        `;
        return;
    }

    // Group findings by URL
    const groupedFindings = new Map();

    // Helper to match domain & referer filters
    const matchesDomainAndReferer = (finding) => {
        if (domainFilter !== "all") {
            let d = finding.domain;
            if (!d && finding.url) {
                try {
                    d = new URL(finding.url).hostname;
                } catch {}
            }
            if (d !== domainFilter) return false;
        }
        if (refererFilter !== "all") {
            let r = finding.refererDomain;
            if (!r && finding.referer) {
                try {
                    r = new URL(finding.referer).hostname;
                } catch {}
            }
            if (r !== refererFilter) return false;
        }
        return true;
    };

    // Process security findings
    if (categoryFilter !== "vulnerableLibraries") {
        securityFindings.forEach((finding) => {
            if (!matchesDomainAndReferer(finding)) return;
            const url = finding.url;
            if (!groupedFindings.has(url)) {
                groupedFindings.set(url, {
                    url: url,
                    requestId: finding.requestId,
                    requestNumber: finding.requestNumber,
                    items: [],
                });
            }

            const group = groupedFindings.get(url);

            // Add items based on category filter
            const categories =
                categoryFilter === "all"
                    ? [
                          "apiKeys",
                          "credentials",
                          "emails",
                          "apiEndpoints",
                          "parameters",
                          "paths",
                      ]
                    : [categoryFilter];

            categories.forEach((cat) => {
                if (finding[cat]) {
                    finding[cat].forEach((item) => {
                        // Apply severity filter
                        if (
                            severityFilter !== "all" &&
                            item.severity !== severityFilter
                        ) {
                            return;
                        }

                        // Apply search filter
                        if (searchTerm) {
                            const searchable =
                                `${item.type} ${item.match} ${item.context || ""}`.toLowerCase();
                            if (!searchable.includes(searchTerm)) {
                                return;
                            }
                        }

                        group.items.push({
                            ...item,
                            category: cat,
                            requestId: finding.requestId,
                            sourceUrl: finding.url,
                        });
                    });
                }
            });
        });
    }

    // Process library findings - merge same library+version vulnerabilities
    if (categoryFilter === "all" || categoryFilter === "vulnerableLibraries") {
        // First, collect all vulnerabilities per library+version
        const libraryVulnMap = new Map(); // key: "url|library|version" -> { vulns: [], ... }

        libraryFindings.forEach((finding) => {
            if (!matchesDomainAndReferer(finding)) return;
            const url = finding.url;

            (finding.libraries || []).forEach((lib) => {
                const key = `${url}|${lib.library}|${lib.version}`;

                if (!libraryVulnMap.has(key)) {
                    libraryVulnMap.set(key, {
                        url: url,
                        library: lib.library,
                        version: lib.version,
                        detectedVia: lib.detectedVia,
                        requestId: finding.requestId,
                        vulnerabilities: [],
                    });
                }

                const entry = libraryVulnMap.get(key);
                (lib.vulnerabilities || []).forEach((vuln) => {
                    // Avoid duplicate vulnerabilities
                    const vulnKey = vuln.summary + (vuln.cve?.join(",") || "");
                    if (
                        !entry.vulnerabilities.some(
                            (v) =>
                                v.summary + (v.cve?.join(",") || "") ===
                                vulnKey,
                        )
                    ) {
                        entry.vulnerabilities.push(vuln);
                    }
                });
            });
        });

        // Now add merged entries to groups
        libraryVulnMap.forEach((libEntry) => {
            const url = libEntry.url;

            if (!groupedFindings.has(url)) {
                groupedFindings.set(url, {
                    url: url,
                    requestId: libEntry.requestId,
                    items: [],
                });
            }

            const group = groupedFindings.get(url);

            // Filter vulnerabilities by severity
            let filteredVulns = libEntry.vulnerabilities;
            if (severityFilter !== "all") {
                filteredVulns = filteredVulns.filter(
                    (v) => v.severity === severityFilter,
                );
            }

            // Apply search filter
            if (searchTerm) {
                const searchable =
                    `${libEntry.library} ${libEntry.version} ${filteredVulns.map((v) => v.summary + " " + (v.cve?.join(" ") || "")).join(" ")}`.toLowerCase();
                if (!searchable.includes(searchTerm)) {
                    return;
                }
            }

            if (filteredVulns.length === 0) return;

            // Determine highest severity for merged entry
            const severityOrder = {
                critical: 4,
                high: 3,
                medium: 2,
                low: 1,
                info: 0,
            };
            const highestSeverity = filteredVulns.reduce((highest, v) => {
                return severityOrder[v.severity] > severityOrder[highest]
                    ? v.severity
                    : highest;
            }, "info");

            group.items.push({
                type: `Vulnerable Library: ${libEntry.library}`,
                match: `${libEntry.library}@${libEntry.version}`,
                severity: highestSeverity,
                isMerged: filteredVulns.length > 1,
                mergedCount: filteredVulns.length,
                isLibrary: true,
                library: libEntry.library,
                version: libEntry.version,
                detectedVia: libEntry.detectedVia,
                vulnerabilities: filteredVulns, // All vulnerabilities for this lib
                requestId: libEntry.requestId,
                sourceUrl: libEntry.url,
            });
        });
    }

    // Render grouped findings
    let hasItems = false;

    groupedFindings.forEach((group, url) => {
        if (group.items.length === 0) return;
        hasItems = true;

        const groupEl = document.createElement("div");
        groupEl.className = "finding-group";

        // Group header
        const headerEl = document.createElement("div");
        headerEl.className = "finding-group-header";
        headerEl.style.display = "flex";
        headerEl.style.alignItems = "center";
        headerEl.style.justifyContent = "space-between";

        const headerSummary = document.createElement("div");
        headerSummary.style.cssText =
            "display:flex;align-items:center;gap:8px;overflow:hidden;flex:1;";
        const urlElement = createTextElement("span", "finding-group-url", url);
        urlElement.title = String(url ?? "");
        headerSummary.append(
            urlElement,
            createTextElement(
                "span",
                "finding-group-count",
                group.items.length,
            ),
        );
        headerEl.appendChild(headerSummary);

        if (group.requestId) {
            const gotoBtn = createTextElement(
                "button",
                "finding-action-btn finding-goto-btn",
                "Go to Request ↗",
            );
            gotoBtn.dataset.requestId = String(group.requestId);
            gotoBtn.addEventListener("click", (e) => {
                e.stopPropagation();
                navigateToRequest(group.requestId);
            });
            headerEl.appendChild(gotoBtn);
        }

        // Group items container
        const itemsEl = document.createElement("div");
        itemsEl.className = "finding-group-items";

        group.items.forEach((item, index) => {
            const itemEl = item.isLibrary
                ? createLibraryFindingElement(
                      item,
                      `${group.requestId}-lib-${index}`,
                  )
                : createFindingItemElement(item, `${group.requestId}-${index}`);
            itemsEl.appendChild(itemEl);
        });

        groupEl.appendChild(headerEl);
        groupEl.appendChild(itemsEl);
        securityFindingsList.appendChild(groupEl);
    });

    if (!hasItems) {
        securityFindingsList.innerHTML = `
            <div class="security-no-findings">
                <p>No findings match the current filters.</p>
            </div>
        `;
    }
}

/**
 * Navigate to a request from a security finding.
 * Closes the security modal, selects the request, and scrolls to it.
 */
function navigateToRequest(requestId) {
    // Close the security modal
    securityModal.classList.remove("show");

    // Find the request
    const request = requests.find((r) => r.id === requestId);
    if (!request) return;

    let needsReRender = false;

    // Reset search filter if active and hiding the target request
    if (searchInput && searchInput.value) {
        searchInput.value = "";
        needsReRender = true;
    }

    // Unhide request type if hidden by filter checkboxes (e.g. script, stylesheet, image)
    if (request.type && hiddenTypes.has(request.type)) {
        hiddenTypes.delete(request.type);
        document.querySelectorAll(".filter-checkbox input").forEach((cb) => {
            if (cb.dataset.type === request.type) cb.checked = true;
        });
        needsReRender = true;
    }

    if (needsReRender) {
        renderRequestList();
    }

    // Select the request
    selectedRequest = request;
    displayRequestDetails(request);

    // Highlight and scroll to the row in the request list
    setTimeout(() => {
        const rows = document.querySelectorAll("#requestList tr");
        let foundRow = false;
        rows.forEach((row) => {
            if (row.dataset.requestId === requestId) {
                row.classList.add("selected");
                row.scrollIntoView({ behavior: "smooth", block: "center" });
                foundRow = true;
            } else {
                row.classList.remove("selected");
            }
        });

        // Fallback: If row was not found in DOM, re-render request list and try once more
        if (!foundRow) {
            renderRequestList();
            const reRows = document.querySelectorAll("#requestList tr");
            reRows.forEach((row) => {
                if (row.dataset.requestId === requestId) {
                    row.classList.add("selected");
                    row.scrollIntoView({ behavior: "smooth", block: "center" });
                }
            });
        }
    }, 50);
}

/**
 * Create a library vulnerability finding element (merged)
 */
function createTextElement(tagName, className, text) {
    const element = document.createElement(tagName);
    if (className) element.className = className;
    element.textContent = String(text ?? "");
    return element;
}

function appendHighlightedContext(container, context, matchText) {
    const source = String(context ?? "");
    const needle = String(matchText ?? "");
    if (!needle) {
        container.textContent = source;
        return;
    }

    let cursor = 0;
    let index;
    while ((index = source.indexOf(needle, cursor)) !== -1) {
        container.appendChild(
            document.createTextNode(source.slice(cursor, index)),
        );
        container.appendChild(
            createTextElement("mark", "finding-match-highlight", needle),
        );
        cursor = index + needle.length;
    }
    container.appendChild(document.createTextNode(source.slice(cursor)));
}

function createLibraryFindingElement(item, id) {
    const el = document.createElement("div");
    el.className = "finding-item library-finding";
    el.id = `finding-${id}`;

    const severity = normalizeFindingSeverity(item.severity, "medium");
    const vulns = item.vulnerabilities || [item.vulnerability]; // Support both merged and single
    const mergedCount =
        Number.isSafeInteger(item.mergedCount) && item.mergedCount > 0
            ? item.mergedCount
            : vulns.length;

    // Create header with merged badge if applicable
    const header = document.createElement("div");
    header.className = "finding-header";
    header.appendChild(
        createTextElement("span", `finding-severity ${severity}`, severity),
    );
    if (item.isMerged) {
        header.appendChild(
            createTextElement(
                "span",
                "finding-merged-badge",
                `MERGED ×${mergedCount}`,
            ),
        );
    }
    const type = document.createElement("span");
    type.className = "finding-type library-type";
    type.appendChild(createTextElement("span", "library-icon", "📦"));
    type.appendChild(
        document.createTextNode(
            ` ${String(item.library ?? "")} @ ${String(item.version ?? "")}`,
        ),
    );
    header.appendChild(type);
    header.appendChild(
        createTextElement("span", "finding-detected-via", item.detectedVia),
    );
    header.appendChild(createTextElement("span", "finding-toggle", "▼"));

    // Create body with all vulnerability details
    const body = document.createElement("div");
    body.className = "finding-body library-body";
    body.id = `finding-body-${id}`;

    const cards = document.createElement("div");
    cards.className = "vuln-cards";
    vulns.filter(Boolean).forEach((vuln) => {
        const vulnSeverity = normalizeFindingSeverity(vuln.severity, "medium");
        const card = document.createElement("div");
        card.className = `vuln-card ${vulnSeverity}`;
        const cardHeader = document.createElement("div");
        cardHeader.className = "vuln-card-header";
        cardHeader.appendChild(
            createTextElement(
                "span",
                `vuln-card-severity ${vulnSeverity}`,
                vulnSeverity,
            ),
        );

        const cves = Array.isArray(vuln.cve) ? vuln.cve : [];
        if (cves.length === 0) {
            cardHeader.appendChild(
                createTextElement("span", "no-cve", "No CVE"),
            );
        } else {
            cves.forEach((cve) => {
                const link = createTextElement("a", "cve-link", cve);
                link.href =
                    "https://nvd.nist.gov/vuln/detail/" +
                    encodeURIComponent(String(cve));
                link.target = "_blank";
                link.rel = "noopener noreferrer";
                cardHeader.append(link, document.createTextNode(" "));
            });
        }
        card.appendChild(cardHeader);
        card.appendChild(
            createTextElement(
                "div",
                "vuln-summary",
                vuln.summary || "No description available",
            ),
        );

        const details = document.createElement("div");
        details.className = "vuln-details";
        const cwes = Array.isArray(vuln.cwe) ? vuln.cwe : [];
        if (cwes.length > 0) {
            const cweContainer = document.createElement("div");
            cweContainer.className = "vuln-cwes";
            cwes.forEach((cwe) => {
                cweContainer.appendChild(
                    createTextElement("span", "cwe-tag", cwe),
                );
            });
            details.appendChild(cweContainer);
        }
        if (vuln.below) {
            const affected = document.createElement("div");
            affected.className = "vuln-version";
            affected.appendChild(createTextElement("strong", "", "Affected:"));
            affected.appendChild(
                document.createTextNode(
                    ` < ${String(vuln.below)}` +
                        (vuln.atOrAbove
                            ? ` (≥ ${String(vuln.atOrAbove)})`
                            : ""),
                ),
            );
            details.appendChild(affected);
        }

        const safeInfoUrls = (Array.isArray(vuln.info) ? vuln.info : [])
            .slice(0, 3)
            .filter(isSafeHttpUrl);
        if (safeInfoUrls.length > 0) {
            const info = document.createElement("div");
            info.className = "vuln-info";
            safeInfoUrls.forEach((url) => {
                const link = createTextElement(
                    "a",
                    "info-link",
                    new URL(url).hostname,
                );
                link.href = url;
                link.target = "_blank";
                link.rel = "noopener noreferrer";
                link.title = url;
                info.append(link, document.createTextNode(" "));
            });
            details.appendChild(info);
        }
        card.appendChild(details);
        cards.appendChild(card);
    });
    body.appendChild(cards);

    if (item.sourceUrl) {
        const sourceUrl = String(item.sourceUrl);
        const sourceDisplay =
            sourceUrl.length > 80 ? "..." + sourceUrl.slice(-77) : sourceUrl;
        const source = document.createElement("div");
        source.className = "finding-source";
        source.appendChild(
            createTextElement("span", "finding-source-label", "Source:"),
        );
        source.appendChild(document.createTextNode(" "));
        const sourceLink = createTextElement(
            "a",
            "finding-source-link",
            sourceDisplay,
        );
        sourceLink.title = sourceUrl;
        source.appendChild(sourceLink);
        body.appendChild(source);
    }

    // Attach click handler on source link to navigate to the request
    if (item.sourceUrl && item.requestId) {
        const sourceLink = body.querySelector(".finding-source-link");
        if (sourceLink) {
            sourceLink.addEventListener("click", (e) => {
                e.stopPropagation();
                navigateToRequest(item.requestId);
            });
        }
    }

    // Add click event listener to header
    header.addEventListener("click", () => {
        const toggle = header.querySelector(".finding-toggle");
        if (body.classList.contains("expanded")) {
            body.classList.remove("expanded");
            toggle.textContent = "▼";
        } else {
            body.classList.add("expanded");
            toggle.textContent = "▲";
        }
    });

    el.appendChild(header);
    el.appendChild(body);
    return el;
}

/**
 * Create a finding item element
 */
function createFindingItemElement(item, id) {
    const el = document.createElement("div");
    el.className = "finding-item";
    el.id = `finding-${id}`;

    const severity = normalizeFindingSeverity(item.severity, "info");

    // Create header
    const header = document.createElement("div");
    header.className = "finding-header";
    header.append(
        createTextElement("span", `finding-severity ${severity}`, severity),
        createTextElement("span", "finding-type", item.type),
        createTextElement("span", "finding-toggle", "▼"),
    );

    // Create body
    const body = document.createElement("div");
    body.className = "finding-body";
    body.id = `finding-body-${id}`;

    // Truncate source URL for display
    const sourceUrl = item.sourceUrl ? String(item.sourceUrl) : "";
    const sourceDisplay = sourceUrl
        ? sourceUrl.length > 80
            ? "..." + sourceUrl.slice(-77)
            : sourceUrl
        : "";

    const rawVal = String(item.extractedValue ?? item.match ?? "");
    const isSensitiveCategory =
        ["apiKeys", "credentials", "secrets"].includes(item.category) ||
        ["critical", "high"].includes(severity);

    const maskValue = (value) => {
        const str = String(value ?? "");
        if (!str) return "";
        if (str.length <= 8) return "••••••••";
        return (
            str.substring(0, 4) +
            "•".repeat(Math.min(12, str.length - 8)) +
            str.slice(-4)
        );
    };

    const maskedVal = isSensitiveCategory ? maskValue(rawVal) : rawVal;

    const matchRow = document.createElement("div");
    matchRow.style.cssText =
        "display:flex;align-items:center;justify-content:space-between;" +
        "gap:10px;margin-bottom:8px;";
    const matchElement = createTextElement("div", "finding-match", maskedVal);
    matchElement.style.cssText = "margin-bottom:0;flex:1;";
    const actions = document.createElement("div");
    actions.style.cssText = "display:flex;gap:6px;flex-shrink:0;";
    if (isSensitiveCategory) {
        const maskButton = createTextElement(
            "button",
            "finding-action-btn mask-btn",
            "👁️ Unmask",
        );
        maskButton.title = "Toggle masking";
        actions.appendChild(maskButton);
    }
    const copyButton = createTextElement(
        "button",
        "finding-action-btn copy-btn",
        "📋 Copy",
    );
    copyButton.title = "Copy to clipboard";
    actions.appendChild(copyButton);
    matchRow.append(matchElement, actions);
    body.appendChild(matchRow);

    if (item.context) {
        const context = document.createElement("div");
        context.className = "finding-context";
        appendHighlightedContext(context, item.context, item.match);
        body.appendChild(context);
    }

    const meta = document.createElement("div");
    meta.className = "finding-meta";
    if (item.line !== undefined && item.line !== null && item.line !== "") {
        meta.appendChild(createTextElement("span", "", `Line: ${item.line}`));
    }
    if (item.extractedValue && item.extractedValue !== item.match) {
        const extracted = String(item.extractedValue);
        meta.appendChild(
            createTextElement(
                "span",
                "",
                "Value: " +
                    (isSensitiveCategory
                        ? maskValue(extracted)
                        : extracted.substring(0, 50)),
            ),
        );
    }
    body.appendChild(meta);

    if (sourceUrl) {
        const source = document.createElement("div");
        source.className = "finding-source";
        source.appendChild(
            createTextElement("span", "finding-source-label", "Source:"),
        );
        source.appendChild(document.createTextNode(" "));
        const sourceLink = createTextElement(
            "a",
            "finding-source-link",
            sourceDisplay,
        );
        sourceLink.title = sourceUrl;
        source.appendChild(sourceLink);
        body.appendChild(source);
    }

    // Attach Copy button event listener
    const copyBtn = body.querySelector(".copy-btn");
    if (copyBtn) {
        copyBtn.addEventListener("click", (e) => {
            e.stopPropagation();
            if (navigator.clipboard?.writeText) {
                navigator.clipboard
                    .writeText(rawVal)
                    .then(() => {
                        copyBtn.textContent = "Copied!";
                        setTimeout(() => {
                            copyBtn.textContent = "📋 Copy";
                        }, 1500);
                    })
                    .catch(() => {
                        copyBtn.textContent = "Copy failed";
                        setTimeout(() => {
                            copyBtn.textContent = "📋 Copy";
                        }, 1500);
                    });
            } else {
                copyBtn.textContent = "Copy failed";
                setTimeout(() => {
                    copyBtn.textContent = "📋 Copy";
                }, 1500);
            }
        });
    }

    // Attach Mask toggle button event listener
    const maskBtn = body.querySelector(".mask-btn");
    if (maskBtn) {
        let isMasked = true;
        maskBtn.addEventListener("click", (e) => {
            e.stopPropagation();
            const matchEl = body.querySelector(".finding-match");
            if (!matchEl) return;
            if (isMasked) {
                matchEl.textContent = rawVal;
                maskBtn.textContent = "🔒 Mask";
                isMasked = false;
            } else {
                matchEl.textContent = maskedVal;
                maskBtn.textContent = "👁️ Unmask";
                isMasked = true;
            }
        });
    }

    // Attach click handler on source link to navigate to the request
    if (item.sourceUrl && item.requestId) {
        const sourceLink = body.querySelector(".finding-source-link");
        if (sourceLink) {
            sourceLink.addEventListener("click", (e) => {
                e.stopPropagation();
                navigateToRequest(item.requestId);
            });
        }
    }

    // Add click event listener to header
    header.addEventListener("click", () => {
        const toggle = header.querySelector(".finding-toggle");
        if (body.classList.contains("expanded")) {
            body.classList.remove("expanded");
            toggle.textContent = "▼";
        } else {
            body.classList.add("expanded");
            toggle.textContent = "▲";
        }
    });

    el.appendChild(header);
    el.appendChild(body);

    return el;
}

/**
 * Export security findings to JSON file
 */
function exportSecurityFindings(findings, filename) {
    const data = JSON.stringify(findings, null, 2);
    const blob = new Blob([data], { type: "application/json" });
    const url = URL.createObjectURL(blob);

    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

/**
 * Display security findings for a specific request in the Security tab
 */
function displayRequestSecurityFindings(request) {
    const securityTabContent = document.getElementById("securityTabContent");

    if (!request || !requestFindings.has(request.id)) {
        securityTabContent.innerHTML = `
            <div class="security-no-findings">
                <p>No security findings for this request.</p>
            </div>
        `;
        securityTabBtn.style.display = "none";
        return;
    }

    const findings = requestFindings.get(request.id);

    // Show the security tab
    securityTabBtn.style.display = "inline-flex";

    // Update tab badge
    const totalCount =
        findings.apiKeys.length +
        findings.credentials.length +
        findings.emails.length +
        findings.apiEndpoints.length +
        findings.paths.length;

    if (totalCount > 0) {
        securityTabBadge.textContent = totalCount;
        securityTabBadge.style.display = "inline-flex";
    } else {
        securityTabBadge.style.display = "none";
    }

    // Render findings
    securityTabContent.innerHTML = "";

    const categories = [
        { key: "apiKeys", label: "API Keys", severity: "critical" },
        { key: "credentials", label: "Credentials", severity: "critical" },
        { key: "emails", label: "Emails", severity: "info" },
        { key: "apiEndpoints", label: "API Endpoints", severity: "info" },
        { key: "parameters", label: "Parameters", severity: "info" },
        { key: "paths", label: "Paths", severity: "info" },
    ];

    categories.forEach((cat) => {
        const items = findings[cat.key];
        if (!items || items.length === 0) return;

        const section = document.createElement("div");
        section.className = "finding-group";

        const header = document.createElement("div");
        header.className = "finding-group-header";
        header.append(
            createTextElement("span", "finding-group-url", cat.label),
            createTextElement("span", "finding-group-count", items.length),
        );

        const itemsContainer = document.createElement("div");
        itemsContainer.className = "finding-group-items";

        items.forEach((item, index) => {
            const itemEl = createFindingItemElement(
                item,
                `tab-${cat.key}-${index}`,
            );
            itemsContainer.appendChild(itemEl);
        });

        section.appendChild(header);
        section.appendChild(itemsContainer);
        securityTabContent.appendChild(section);
    });
}

captureToggle.addEventListener("change", () => {
    // If capture is turned off, also turn off intercept
    if (!captureToggle.checked && interceptToggle.checked) {
        interceptToggle.checked = false;
        port.postMessage({ type: "toggleIntercept", enabled: false });
    }
    port.postMessage({ type: "toggleCapture", enabled: captureToggle.checked });
});

interceptToggle.addEventListener("change", () => {
    // If intercept is turned on, also turn on capture
    if (interceptToggle.checked && !captureToggle.checked) {
        captureToggle.checked = true;
        port.postMessage({ type: "toggleCapture", enabled: true });
    }
    port.postMessage({
        type: "toggleIntercept",
        enabled: interceptToggle.checked,
    });
});

clearBtn.addEventListener("click", () => {
    requests = [];
    requestCounter = 0;
    renderRequestList();
    clearRequestDetails();
    port.postMessage({ type: "clearRequests" });
});

filterBtn.addEventListener("click", () => {
    const isVisible = filterPanel.style.display !== "none";
    filterPanel.style.display = isVisible ? "none" : "block";
    filterBtn.textContent = isVisible ? "Filters ▼" : "Filters ▲";
});

themeToggleBtn.addEventListener("click", () => {
    toggleTheme();
});

document
    .querySelectorAll(".filter-checkbox input[data-type]")
    .forEach((checkbox) => {
        checkbox.addEventListener("change", () => {
            const type = checkbox.dataset.type;
            if (!type) return;
            if (checkbox.checked) {
                hiddenTypes.add(type);
            } else {
                hiddenTypes.delete(type);
            }
            localStorage.setItem(
                "hiddenTypes",
                JSON.stringify(Array.from(hiddenTypes)),
            );
            updateActiveFilterBadge();
            renderRequestList();
        });
    });

// One-time version migration for DevTools panel
try {
    const currentManifestVersion = browser.runtime.getManifest().version;
    const lastPanelVersion = localStorage.getItem("lastPanelVersion");

    if (lastPanelVersion !== currentManifestVersion) {
        console.log(
            `[Version Migration] Upgraded to v${currentManifestVersion} (previous: ${lastPanelVersion || "none"}). Clearing legacy hiddenTypes.`,
        );
        localStorage.removeItem("hiddenTypes");
        localStorage.setItem("lastPanelVersion", currentManifestVersion);
        hiddenTypes.clear();
    }
} catch (e) {
    console.warn(
        "[Version Migration] Warning checking panel version migration:",
        e,
    );
}

const savedHiddenTypes = localStorage.getItem("hiddenTypes");
if (savedHiddenTypes) {
    try {
        const parsed = JSON.parse(savedHiddenTypes);
        const validTypes = Array.isArray(parsed)
            ? parsed.filter((t) => t && typeof t === "string")
            : [];
        hiddenTypes = new Set(validTypes);
        hiddenTypes.forEach((type) => {
            const checkbox = document.querySelector(
                `input[data-type="${type}"]`,
            );
            if (checkbox) checkbox.checked = true;
        });
    } catch {
        localStorage.removeItem("hiddenTypes");
    }
}

searchInput.addEventListener("input", () => {
    renderRequestList();
});

// ==========================================
// EXPANDED FILTER PANEL LOGIC & HELPERS
// ==========================================

function renderDomainFilterList() {
    if (!domainFilterList) return;
    const capturedDomains = new Set();
    requests.forEach((r) => {
        if (!r.url) return;
        try {
            const host = new URL(r.url).hostname;
            if (host) capturedDomains.add(host);
        } catch {}
    });

    const search = (domainSearchInput ? domainSearchInput.value : "")
        .toLowerCase()
        .trim();
    const sortedDomains = Array.from(capturedDomains).sort();
    const matchingDomains = sortedDomains.filter(
        (d) => !search || d.toLowerCase().includes(search),
    );

    domainFilterList.innerHTML = "";
    if (matchingDomains.length === 0) {
        domainFilterList.innerHTML =
            '<div class="domain-empty-hint">No matching domains</div>';
        return;
    }

    matchingDomains.forEach((dom) => {
        const item = document.createElement("label");
        item.className = "domain-item";
        const isChecked =
            selectedDomains.size === 0 || selectedDomains.has(dom);
        const cb = document.createElement("input");
        cb.type = "checkbox";
        cb.dataset.domain = dom;
        cb.checked = isChecked;
        item.append(cb, createTextElement("span", "", dom));
        cb.addEventListener("change", () => {
            if (selectedDomains.size === 0) {
                sortedDomains.forEach((d) => selectedDomains.add(d));
            }
            if (cb.checked) {
                selectedDomains.add(dom);
                if (selectedDomains.size >= sortedDomains.length) {
                    selectedDomains.clear();
                }
            } else {
                selectedDomains.delete(dom);
            }
            updateActiveFilterBadge();
            renderRequestList();
        });
        domainFilterList.appendChild(item);
    });
}

function updateActiveFilterBadge() {
    let count = 0;
    count += hiddenTypes.size;
    if (selectedMethods.size < 7) count += 7 - selectedMethods.size;
    if (selectedStatusGroups.size < 5) count += 5 - selectedStatusGroups.size;
    if (selectedDomains.size > 0) count += 1;
    if (securityOnlyFilter) count += 1;

    if (activeFilterBadge) {
        if (count > 0) {
            activeFilterBadge.textContent = count;
            activeFilterBadge.style.display = "inline-flex";
        } else {
            activeFilterBadge.style.display = "none";
        }
    }
}

function resetAllFilters() {
    hiddenTypes.clear();
    localStorage.removeItem("hiddenTypes");
    document
        .querySelectorAll(".filter-options input[data-type]")
        .forEach((cb) => (cb.checked = false));

    selectedMethods = new Set([
        "GET",
        "POST",
        "PUT",
        "DELETE",
        "PATCH",
        "OPTIONS",
        "HEAD",
    ]);
    document
        .querySelectorAll("#methodFilterOptions input")
        .forEach((cb) => (cb.checked = true));

    selectedStatusGroups = new Set(["2xx", "3xx", "4xx", "5xx", "0"]);
    document
        .querySelectorAll("#statusFilterOptions input")
        .forEach((cb) => (cb.checked = true));

    selectedDomains.clear();
    if (domainSearchInput) domainSearchInput.value = "";

    securityOnlyFilter = false;
    if (filterSecurityOnly) filterSecurityOnly.checked = false;

    updateActiveFilterBadge();
    renderDomainFilterList();
    renderRequestList();
}

// Method Filter Listeners
document
    .querySelectorAll("#methodFilterOptions input[data-method]")
    .forEach((cb) => {
        cb.addEventListener("change", () => {
            const method = cb.dataset.method;
            if (cb.checked) {
                selectedMethods.add(method);
            } else {
                selectedMethods.delete(method);
            }
            updateActiveFilterBadge();
            renderRequestList();
        });
    });

// Status Code Filter Listeners
document
    .querySelectorAll("#statusFilterOptions input[data-status]")
    .forEach((cb) => {
        cb.addEventListener("change", () => {
            const status = cb.dataset.status;
            if (cb.checked) {
                selectedStatusGroups.add(status);
            } else {
                selectedStatusGroups.delete(status);
            }
            updateActiveFilterBadge();
            renderRequestList();
        });
    });

// Security Only Filter Listener
if (filterSecurityOnly) {
    filterSecurityOnly.addEventListener("change", () => {
        securityOnlyFilter = filterSecurityOnly.checked;
        updateActiveFilterBadge();
        renderRequestList();
    });
}

// Domain Search Input
if (domainSearchInput) {
    domainSearchInput.addEventListener("input", () => {
        renderDomainFilterList();
    });
}

// Domain Select All
if (domainSelectAllBtn) {
    domainSelectAllBtn.addEventListener("click", () => {
        selectedDomains.clear();
        updateActiveFilterBadge();
        renderDomainFilterList();
        renderRequestList();
    });
}

// Domain Clear All
if (domainClearAllBtn) {
    domainClearAllBtn.addEventListener("click", () => {
        selectedDomains.clear();
        selectedDomains.add("__NONE__");
        updateActiveFilterBadge();
        renderDomainFilterList();
        renderRequestList();
    });
}

// Filter Preset Buttons
document.querySelectorAll(".filter-preset-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
        const preset = btn.dataset.preset;
        if (preset === "xhr") {
            [
                "image",
                "script",
                "stylesheet",
                "font",
                "media",
                "websocket",
            ].forEach((t) => hiddenTypes.add(t));
            document
                .querySelectorAll(".filter-options input[data-type]")
                .forEach((cb) => (cb.checked = true));
            selectedMethods = new Set([
                "GET",
                "POST",
                "PUT",
                "DELETE",
                "PATCH",
                "OPTIONS",
                "HEAD",
            ]);
            document
                .querySelectorAll("#methodFilterOptions input")
                .forEach((cb) => (cb.checked = true));
            selectedStatusGroups = new Set(["2xx", "3xx", "4xx", "5xx", "0"]);
            document
                .querySelectorAll("#statusFilterOptions input")
                .forEach((cb) => (cb.checked = true));
        } else if (preset === "failed") {
            selectedStatusGroups = new Set(["4xx", "5xx", "0"]);
            document
                .querySelectorAll("#statusFilterOptions input")
                .forEach((cb) => {
                    cb.checked = ["4xx", "5xx", "0"].includes(
                        cb.dataset.status,
                    );
                });
        } else if (preset === "mutating") {
            selectedMethods = new Set(["POST", "PUT", "PATCH", "DELETE"]);
            document
                .querySelectorAll("#methodFilterOptions input")
                .forEach((cb) => {
                    cb.checked = ["POST", "PUT", "PATCH", "DELETE"].includes(
                        cb.dataset.method,
                    );
                });
        } else if (preset === "all") {
            resetAllFilters();
            return;
        }
        updateActiveFilterBadge();
        renderRequestList();
    });
});

if (resetAllFiltersBtn) {
    resetAllFiltersBtn.addEventListener("click", () => {
        resetAllFilters();
    });
}

// Restore the last sort preference; otherwise show newest requests first.
try {
    const savedSort = JSON.parse(localStorage.getItem("requestSort"));
    const columns = Array.from(
        document.querySelectorAll("#requestTable th[data-column]"),
        (th) => th.dataset.column,
    );
    if (
        columns.includes(savedSort?.column) &&
        ["asc", "desc"].includes(savedSort?.direction)
    ) {
        currentSortColumn = savedSort.column;
        currentSortDirection = savedSort.direction;
    }
} catch (err) {
    console.error("Failed to load request sort preference:", err);
}
updateSortIndicators();

// Add sorting functionality to table headers
document.querySelectorAll("#requestTable th[data-column]").forEach((th) => {
    th.addEventListener("click", () => {
        const column = th.dataset.column;
        if (currentSortColumn === column) {
            currentSortDirection =
                currentSortDirection === "asc" ? "desc" : "asc";
        } else {
            currentSortColumn = column;
            currentSortDirection = "asc";
        }
        try {
            localStorage.setItem(
                "requestSort",
                JSON.stringify({
                    column: currentSortColumn,
                    direction: currentSortDirection,
                }),
            );
        } catch (err) {
            console.error("Failed to save request sort preference:", err);
        }
        updateSortIndicators();
        renderRequestList();
    });
});

// Add search functionality for request/response/modified content
requestSearchInput.addEventListener("input", () => {
    const searchTerm = requestSearchInput.value;
    highlightContent("requestContent", searchTerm, requestSearchCount);
});

modifiedSearchInput.addEventListener("input", () => {
    const searchTerm = modifiedSearchInput.value;
    highlightContent("modifiedContent", searchTerm, modifiedSearchCount);
});

responseSearchInput.addEventListener("input", () => {
    const searchTerm = responseSearchInput.value;
    highlightContent("responseContent", searchTerm, responseSearchCount);
});

document.querySelectorAll(".tab-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
        const tab = btn.dataset.tab;
        currentTab = tab;

        document
            .querySelectorAll(".tab-btn")
            .forEach((b) => b.classList.remove("active"));
        btn.classList.add("active");

        document.getElementById("requestTab").style.display =
            tab === "request" ? "flex" : "none";
        document.getElementById("modifiedTab").style.display =
            tab === "modified" ? "flex" : "none";
        document.getElementById("responseTab").style.display =
            tab === "response" ? "flex" : "none";
        document.getElementById("securityTab").style.display =
            tab === "security" ? "flex" : "none";

        if (selectedRequest) {
            displayRequestDetails(selectedRequest);
        }
    });
});

document.querySelectorAll("#requestTab .view-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
        const view = btn.dataset.view;
        currentRequestView = view;

        btn.parentElement
            .querySelectorAll(".view-btn")
            .forEach((b) => b.classList.remove("active"));
        btn.classList.add("active");

        if (selectedRequest) {
            displayRequestDetails(selectedRequest);
        }
    });
});

document.querySelectorAll("#modifiedTab .view-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
        const view = btn.dataset.view;
        currentModifiedView = view;

        btn.parentElement
            .querySelectorAll(".view-btn")
            .forEach((b) => b.classList.remove("active"));
        btn.classList.add("active");

        if (selectedRequest) {
            displayRequestDetails(selectedRequest);
        }
    });
});

document.querySelectorAll("#responseTab .view-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
        const view = btn.dataset.view;
        currentResponseView = view;

        btn.parentElement
            .querySelectorAll(".view-btn")
            .forEach((b) => b.classList.remove("active"));
        btn.classList.add("active");

        if (selectedRequest) {
            displayRequestDetails(selectedRequest);
        }
    });
});

copyCurlBtn.addEventListener("click", () => {
    if (selectedRequest) {
        const curl = generateCurl(selectedRequest);
        navigator.clipboard.writeText(curl).then(() => {
            copyCurlBtn.textContent = "Copied!";
            setTimeout(() => {
                copyCurlBtn.textContent = "Copy as cURL";
            }, 2000);
        });
    }
});

copyRequestBtn.addEventListener("click", () => {
    if (selectedRequest) {
        const rawContent = formatRequestContent(selectedRequest, "raw");
        navigator.clipboard.writeText(rawContent).then(() => {
            copyRequestBtn.textContent = "Copied!";
            setTimeout(() => {
                copyRequestBtn.textContent = "Copy";
            }, 2000);
        });
    }
});

copyResponseBtn.addEventListener("click", () => {
    if (selectedRequest) {
        const rawContent = formatResponseContent(selectedRequest, "raw");
        navigator.clipboard.writeText(rawContent.content).then(() => {
            copyResponseBtn.textContent = "Copied!";
            setTimeout(() => {
                copyResponseBtn.textContent = "Copy";
            }, 2000);
        });
    }
});

repeaterBtn.addEventListener("click", () => {
    if (selectedRequest) {
        showRepeaterModal(selectedRequest);
    }
});

// Modified request tab buttons
document.getElementById("copyModifiedCurlBtn").addEventListener("click", () => {
    if (selectedRequest && selectedRequest.wasModified) {
        const curl = generateModifiedCurl(selectedRequest);
        navigator.clipboard.writeText(curl).then(() => {
            const btn = document.getElementById("copyModifiedCurlBtn");
            btn.textContent = "Copied!";
            setTimeout(() => {
                btn.textContent = "Copy as cURL";
            }, 2000);
        });
    }
});

document.getElementById("modifiedRepeaterBtn").addEventListener("click", () => {
    if (selectedRequest && selectedRequest.wasModified) {
        showModifiedRepeaterModal(selectedRequest);
    }
});

closeRepeaterBtn.addEventListener("click", () => {
    repeaterModal.classList.remove("show");
});

sendRepeaterBtn.addEventListener("click", () => {
    sendRepeaterRequest();
});

clearRepeaterBtn.addEventListener("click", () => {
    document.getElementById("repeaterStatus").textContent = "No response yet";
    document.getElementById("repeaterStatus").className = "response-status";
    document.getElementById("repeaterResponseContent").textContent = "";
    lastRepeaterResponse = null;
});

document.querySelectorAll(".response-tab-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
        const tab = btn.dataset.tab;
        currentRepeaterTab = tab;

        document
            .querySelectorAll(".response-tab-btn")
            .forEach((b) => b.classList.remove("active"));
        btn.classList.add("active");

        if (lastRepeaterResponse) {
            displayRepeaterResponse(lastRepeaterResponse);
        }
    });
});

function buildInterceptModifiedRequest() {
    if (!interceptedRequest) return null;
    const headersText = document.getElementById("interceptHeaders").value;
    return {
        method: document.getElementById("interceptMethod").value,
        url: document.getElementById("interceptUrl").value,
        headers: parseHeaders(headersText),
        headersText,
        headersEdited: interceptHeadersEdited,
        body: document.getElementById("interceptBody").value,
        bodyEdited: interceptBodyEdited,
        bodyEncoding:
            interceptedRequest.requestBodyModel?.kind === "base64"
                ? "base64"
                : "text",
        bodyEditable: interceptedRequest.requestBodyModel?.editable !== false,
        bodyReplayable:
            interceptedRequest.requestBodyModel?.replayable !== false,
        bodyUnavailableReason: interceptedRequest.requestBodyModel?.reason,
    };
}

function showInterceptValidationErrors(errors = []) {
    const errorElement = document.getElementById("interceptValidationError");
    errorElement.textContent = errors.map((error) => error.message).join("\n");
    errorElement.hidden = errors.length === 0;
}

function getInterceptDecision(modifiedRequest) {
    return RequestInterception.decideInterceptAction(
        interceptedRequest,
        modifiedRequest,
        {
            modifiedRequestAction: interceptSettings.modifiedRequestAction,
            maxBodyBytes: MAX_REPLAY_BODY_BYTES,
        },
    );
}

document.getElementById("forwardBtn").addEventListener("click", () => {
    if (!interceptedRequest) return;

    const modifiedRequest = buildInterceptModifiedRequest();
    const decision = getInterceptDecision(modifiedRequest);
    if (decision.action === "reject-edit") {
        showInterceptValidationErrors(decision.validation.errors);
        updateInterceptForwardAction();
        return;
    }

    if (decision.action === "cancel-and-send") {
        const sensitiveTransfer =
            RequestInterception.getCrossOriginSensitiveHeaders(
                interceptedRequest.url,
                modifiedRequest.url,
                modifiedRequest.headers,
            );
        if (sensitiveTransfer.headerNames.length > 0) {
            const approved = confirm(
                `The target origin changes from ${sensitiveTransfer.originalOrigin} to ${sensitiveTransfer.modifiedOrigin}.\n\n` +
                    `The edited request contains sensitive headers: ${sensitiveTransfer.headerNames.join(", ")}.\n\n` +
                    "Cancel the page request and send these headers to the new origin?",
            );
            if (!approved) return;
        }
    }

    showInterceptValidationErrors([]);
    const forwardButton = document.getElementById("forwardBtn");
    forwardButton.disabled = true;
    forwardButton.textContent =
        decision.action === "cancel-and-send"
            ? "Cancelling & Sending..."
            : "Forwarding...";
    port.postMessage({
        type: "forwardRequest",
        requestId: interceptedRequest.id,
        requestedAction: decision.action,
        modifiedRequest,
    });
});

document.getElementById("dropBtn").addEventListener("click", () => {
    if (interceptedRequest) {
        port.postMessage({
            type: "dropRequest",
            requestId: interceptedRequest.id,
        });

        closeInterceptModal();
    }
});

// Intercept Settings Event Listeners
interceptSettingsBtn.addEventListener("click", () => {
    showInterceptSettingsModal();
});

closeInterceptSettingsBtn.addEventListener("click", () => {
    closeInterceptSettingsModal();
});

saveInterceptSettingsBtn.addEventListener("click", () => {
    saveInterceptSettings();
});

resetInterceptSettingsBtn.addEventListener("click", () => {
    resetInterceptSettings();
});

// GET checkbox warning
document.getElementById("interceptGET").addEventListener("change", (e) => {
    const getWarning = document.getElementById("getWarning");
    getWarning.style.display = e.target.checked ? "block" : "none";
});

// Response interception checkbox warning
document
    .getElementById("interceptResponses")
    .addEventListener("change", (e) => {
        const responseWarning = document.getElementById("responseWarning");
        responseWarning.style.display = e.target.checked ? "block" : "none";
    });

document
    .getElementById("useEarlyInterception")
    .addEventListener("change", (e) => {
        const warning = document.getElementById("earlyInterceptionWarning");
        warning.style.display = e.target.checked ? "block" : "none";
    });

function updateExperimentalSettingControls(preserveEarlySelection = false) {
    const experimentalSelected = document.getElementById(
        "modifiedRequestCancelAndSend",
    ).checked;
    const earlyCheckbox = document.getElementById("useEarlyInterception");
    const warning = document.getElementById("experimentalModeWarning");
    const acknowledgement = document.getElementById(
        "experimentalModeAcknowledged",
    );
    if (!experimentalSelected || preserveEarlySelection) {
        acknowledgement.checked = false;
    }
    acknowledgement.removeAttribute("aria-invalid");
    document.getElementById("experimentalModeSaveError").hidden = true;

    if (
        preserveEarlySelection &&
        experimentalSelected &&
        !earlyCheckbox.disabled
    ) {
        earlyCheckbox.dataset.previousChecked = String(earlyCheckbox.checked);
    }

    warning.style.display = experimentalSelected ? "block" : "none";
    earlyCheckbox.disabled = experimentalSelected;
    if (experimentalSelected) {
        earlyCheckbox.checked = false;
        document.getElementById("earlyInterceptionWarning").style.display =
            "none";
    } else if (
        preserveEarlySelection &&
        earlyCheckbox.dataset.previousChecked !== undefined
    ) {
        earlyCheckbox.checked =
            earlyCheckbox.dataset.previousChecked === "true";
        document.getElementById("earlyInterceptionWarning").style.display =
            earlyCheckbox.checked ? "block" : "none";
        delete earlyCheckbox.dataset.previousChecked;
    }
}

document
    .getElementById("modifiedRequestRepeaterDraft")
    .addEventListener("change", () => {
        updateExperimentalSettingControls(true);
    });
document
    .getElementById("modifiedRequestCancelAndSend")
    .addEventListener("change", () => {
        updateExperimentalSettingControls(true);
    });

document
    .getElementById("experimentalModeAcknowledged")
    .addEventListener("change", (event) => {
        event.target.removeAttribute("aria-invalid");
        document.getElementById("experimentalModeSaveError").hidden = true;
    });

openExperimentalSettingsBtn.addEventListener("click", () => {
    experimentalPromotionBanner.hidden = true;
    showInterceptSettingsModal({ focusModifiedRequestAction: true });
});

dismissExperimentalPromotionBtn.addEventListener("click", () => {
    experimentalPromotionBanner.hidden = true;
});

forwardResponseBtn.addEventListener("click", () => {
    if (interceptedResponse) {
        const headersText = document.getElementById("responseHeaders").value;
        const modifiedResponse = {
            statusCode: parseInt(
                document.getElementById("responseStatusCode").value,
            ),
            statusText: document.getElementById("responseStatusText").value,
            headers: parseHeaders(headersText),
            headersText,
            headersEdited: responseHeadersEdited,
            body: document.getElementById("responseBody").value,
            bodyEdited: responseBodyEdited,
            bodyEncoding: interceptedResponse.isBase64 ? "base64" : "text",
        };
        const validation = RequestInterception.validateEditedResponse(
            modifiedResponse,
            { maxBodyBytes: 10 * 1024 * 1024 },
        );
        if (!validation.valid) {
            showResponseInterceptValidationErrors(validation.errors);
            return;
        }

        showResponseInterceptValidationErrors([]);
        forwardResponseBtn.disabled = true;

        port.postMessage({
            type: "forwardResponse",
            requestId: interceptedResponse.requestId,
            modifiedResponse: modifiedResponse,
        });
    }
});

dropResponseBtn.addEventListener("click", () => {
    if (interceptedResponse) {
        port.postMessage({
            type: "dropResponse",
            requestId: interceptedResponse.requestId,
        });

        closeResponseInterceptModal();
    }
});

// Disable Intercept event listeners
disableInterceptBtn.addEventListener("click", () => {
    if (interceptedRequest) {
        port.postMessage({
            type: "disableIntercept",
            currentRequestId: interceptedRequest.id,
            currentType: "request",
        });

        closeInterceptModal();
    }
});

disableInterceptResponseBtn.addEventListener("click", () => {
    if (interceptedResponse) {
        port.postMessage({
            type: "disableIntercept",
            currentRequestId: interceptedResponse.requestId,
            currentType: "response",
        });

        closeResponseInterceptModal();
    }
});

// Track manual edits in intercept headers textarea so we don't overwrite user input
document.getElementById("interceptHeaders").addEventListener("input", () => {
    interceptHeadersEdited = true;
    updateInterceptForwardAction();
});

document.getElementById("interceptBody").addEventListener("input", () => {
    interceptBodyEdited = true;
    updateInterceptForwardAction();
});

document
    .getElementById("interceptMethod")
    .addEventListener("change", updateInterceptForwardAction);
document
    .getElementById("interceptUrl")
    .addEventListener("input", updateInterceptForwardAction);

document.getElementById("responseHeaders").addEventListener("input", () => {
    responseHeadersEdited = true;
});

document.getElementById("responseBody").addEventListener("input", () => {
    responseBodyEdited = true;
});

port.onMessage.addListener((msg) => {
    switch (msg.type) {
        case "initialState":
            captureToggle.checked = msg.captureEnabled;
            interceptToggle.checked = msg.interceptEnabled;
            if (msg.interceptSettings) {
                interceptSettings = msg.interceptSettings;
                updateInterceptSettingsUI();
            }
            port.postMessage({ type: "claimExperimentalPromotion" });
            requests = msg.requests;
            // Assign request numbers to existing requests if they don't have them
            requests.forEach((req) => {
                if (req.requestNumber) {
                    requestCounter = Math.max(
                        requestCounter,
                        req.requestNumber,
                    );
                } else {
                    requestCounter++;
                    req.requestNumber = requestCounter;
                }
            });
            // Load security findings from background (captured while DevTools was closed)
            if (msg.securityFindings && msg.securityFindings.length > 0) {
                msg.securityFindings.forEach((finding) => {
                    if (
                        !securityFindings.some(
                            (f) =>
                                f.url === finding.url &&
                                f.timestamp === finding.timestamp,
                        )
                    ) {
                        securityFindings.push(finding);
                    }
                    // Populate per-request findings map so Security tab appears when selecting the request
                    if (
                        finding.requestId &&
                        !requestFindings.has(finding.requestId)
                    ) {
                        requestFindings.set(finding.requestId, finding);
                        const req = requests.find(
                            (r) => r.id === finding.requestId,
                        );
                        if (req) {
                            req.hasSecurityFindings = true;
                            req.securityFindingsCount = finding.totalFindings;
                        }
                    }
                });
                unseenFindingsCount = msg.securityFindings.reduce(
                    (acc, finding) => acc + significantFindingCount(finding),
                    0,
                );
            }
            // Load library findings from background
            if (msg.libraryFindings && msg.libraryFindings.length > 0) {
                msg.libraryFindings.forEach((finding) => {
                    if (
                        !libraryFindings.some(
                            (f) =>
                                f.url === finding.url &&
                                f.timestamp === finding.timestamp,
                        )
                    ) {
                        libraryFindings.push(finding);
                    }
                });
                unseenFindingsCount += msg.libraryFindings.reduce(
                    (acc, f) => acc + f.totalFindings,
                    0,
                );
            }
            updateSecurityBadge();
            renderSecurityFindingsList();
            renderRequestList();
            break;

        case "captureStateChanged":
            captureToggle.checked = msg.enabled;
            break;

        case "interceptStateChanged":
            interceptToggle.checked = msg.enabled;
            break;

        case "newRequest":
            requestCounter++;
            msg.request.requestNumber = requestCounter;
            requests.push(msg.request);
            processPendingHarEntries();
            renderRequestList();
            if (!selectedRequest && requests.length === 1) {
                selectedRequest = msg.request;
                displayRequestDetails(selectedRequest);
            }
            break;

        case "requestEvicted":
            requests = requests.filter(
                (request) => request.id !== msg.requestId,
            );
            requestFindings.delete(msg.requestId);
            requestLibraryFindings.delete(msg.requestId);
            if (selectedRequest?.id === msg.requestId) {
                selectedRequest = null;
                clearRequestDetails();
            }
            renderRequestList();
            break;

        case "updateRequest": {
            const index = requests.findIndex((r) => r.id === msg.request.id);
            if (index !== -1) {
                // Preserve the request number when updating
                msg.request.requestNumber = requests[index].requestNumber;

                // Preserve clearedSecurity flag if request was cleared
                if (requests[index].clearedSecurity) {
                    msg.request.clearedSecurity = true;
                }

                // Preserve security findings if already scanned and not cleared
                if (
                    requests[index].hasSecurityFindings &&
                    !requests[index].clearedSecurity
                ) {
                    msg.request.hasSecurityFindings =
                        requests[index].hasSecurityFindings;
                    msg.request.securityFindingsCount =
                        requests[index].securityFindingsCount;
                }

                requests[index] = msg.request;

                renderRequestList();
                if (selectedRequest && selectedRequest.id === msg.request.id) {
                    selectedRequest = msg.request;
                    displayRequestDetails(selectedRequest);
                }
            }
            break;
        }

        case "interceptRequest":
            interceptQueue.push(msg.request);
            if (!interceptedRequest) {
                processNextIntercept();
            }
            updateQueueCounts();
            break;

        case "interceptResponse":
            responseQueue.push(msg.response);
            if (!interceptedResponse) {
                processNextResponseIntercept();
            }
            updateQueueCounts();
            break;

        case "interceptionReleased":
            if (msg.kind === "request") {
                interceptQueue = interceptQueue.filter(
                    (request) => request.id !== msg.requestId,
                );

                if (interceptedRequest?.id === msg.requestId) {
                    interceptedRequest = null;
                    interceptModal.classList.remove("show");
                    processNextIntercept();
                }
            } else if (msg.kind === "response") {
                responseQueue = responseQueue.filter(
                    (response) => response.requestId !== msg.requestId,
                );

                if (interceptedResponse?.requestId === msg.requestId) {
                    interceptedResponse = null;
                    responseInterceptModal.classList.remove("show");
                    processNextResponseIntercept();
                }
            }

            updateQueueCounts();
            break;

        case "interceptSettingsChanged":
            interceptSettings = msg.settings;
            updateInterceptSettingsUI();
            updateInterceptForwardAction();
            break;

        case "interceptValidationError":
            if (interceptedRequest?.id === msg.requestId) {
                showInterceptValidationErrors(msg.errors || []);
                document.getElementById("forwardBtn").disabled = false;
                updateInterceptForwardAction();
            }
            break;

        case "responseInterceptValidationError":
            if (interceptedResponse?.requestId === msg.requestId) {
                showResponseInterceptValidationErrors(msg.errors || []);
                forwardResponseBtn.disabled = false;
            }
            break;

        case "interceptSettingsResponse":
            interceptSettings = msg.settings;
            updateInterceptSettingsUI();
            break;

        case "requestsCleared":
            requests = [];
            requestCounter = 0;
            // Also clear security and library findings
            securityFindings = [];
            libraryFindings = [];
            requestFindings.clear();
            requestLibraryFindings.clear();
            unseenFindingsCount = 0;
            updateSecurityBadge();
            renderRequestList();
            clearRequestDetails();
            break;

        case "replacementResult":
            showStoredReplacementResult(
                msg.requestId,
                msg.requestData,
                msg.result,
            );
            break;

        case "securityFinding":
            // New security finding from background scanner
            if (
                msg.finding &&
                !securityFindings.some(
                    (f) =>
                        f.url === msg.finding.url &&
                        f.timestamp === msg.finding.timestamp,
                )
            ) {
                securityFindings.push(msg.finding);
                // Mark request as scanned so the updateRequest handler won't re-scan
                if (msg.finding.requestId) {
                    requestFindings.set(msg.finding.requestId, msg.finding);
                }
                unseenFindingsCount += significantFindingCount(msg.finding);
                updateSecurityBadge();
                renderSecurityFindingsList();
            }
            break;

        case "vulnerabilityDbStatus":
            renderVulnerabilityDbStatus(msg.status);
            break;

        case "securityFindingsCleared":
            securityFindings = [];
            requestFindings.clear();
            unseenFindingsCount = 0;
            requests.forEach((req) => {
                req.hasSecurityFindings = false;
                req.securityFindingsCount = 0;
                req.clearedSecurity = true;
            });
            updateSecurityBadge();
            renderSecurityModal();
            renderRequestList();
            break;

        case "securityFindingsResponse":
            // Response to getSecurityFindings request
            if (msg.findings && msg.findings.length > 0) {
                msg.findings.forEach((finding) => {
                    if (
                        !securityFindings.some(
                            (f) =>
                                f.url === finding.url &&
                                f.timestamp === finding.timestamp,
                        )
                    ) {
                        securityFindings.push(finding);
                    }
                });
                unseenFindingsCount = msg.findings.reduce(
                    (acc, finding) => acc + significantFindingCount(finding),
                    0,
                );
                updateSecurityBadge();
                renderSecurityModal();
            }
            break;

        case "libraryFinding":
            // New vulnerable library finding from background scanner
            if (
                msg.finding &&
                !libraryFindings.some(
                    (f) =>
                        f.url === msg.finding.url &&
                        f.timestamp === msg.finding.timestamp,
                )
            ) {
                libraryFindings.push(msg.finding);
                unseenFindingsCount += msg.finding.totalFindings;
                updateSecurityBadge();
                renderSecurityModal();
            }
            break;

        case "libraryFindingsCleared":
            libraryFindings = [];
            requestLibraryFindings.clear();
            updateSecurityBadge();
            renderSecurityModal();
            break;

        case "libraryFindingsResponse":
            // Response to getLibraryFindings request
            if (msg.findings && msg.findings.length > 0) {
                msg.findings.forEach((finding) => {
                    if (
                        !libraryFindings.some(
                            (f) =>
                                f.url === finding.url &&
                                f.timestamp === finding.timestamp,
                        )
                    ) {
                        libraryFindings.push(finding);
                    }
                });
                updateSecurityBadge();
                renderSecurityFindingsList();
            }
            break;

        case "repeaterResponse": {
            if (
                activeReplacementRequestId !== null ||
                activeRepeaterRequestId !== msg.requestId
            )
                break;
            lastRepeaterResponse = msg.response;
            sendRepeaterBtn.disabled = false;
            const statusClass =
                msg.response.status >= 200 && msg.response.status < 300
                    ? "success"
                    : "error";
            const redirectLabel = msg.response.redirected
                ? " • redirected"
                : "";
            document.getElementById("repeaterStatus").textContent =
                `${msg.response.status} ${msg.response.statusText} (${msg.response.duration}ms) • extension-origin${redirectLabel}`;
            document.getElementById("repeaterStatus").className =
                `response-status ${statusClass}`;
            displayRepeaterResponse(msg.response);
            break;
        }

        case "repeaterError":
            if (
                activeReplacementRequestId !== null ||
                activeRepeaterRequestId !== msg.requestId
            )
                break;
            sendRepeaterBtn.disabled = false;
            document.getElementById("repeaterStatus").textContent =
                `Error: ${msg.error}`;
            document.getElementById("repeaterStatus").className =
                "response-status error";
            document.getElementById("repeaterResponseContent").textContent =
                msg.error;
            break;

        case "repeaterDraft":
            showRepeaterDraft(msg.requestData);
            break;

        case "replacementQueued":
            showReplacementRequest(
                msg.requestId,
                msg.requestData,
                "Original cancellation requested — edited request queued",
            );
            break;

        case "replacementStarted":
            if (activeReplacementRequestId !== msg.requestId) break;
            document.getElementById("repeaterStatus").textContent =
                "Original cancelled — sending edited extension-origin request...";
            document.getElementById("repeaterStatus").className =
                "response-status";
            break;

        case "replacementResponse":
            if (activeReplacementRequestId !== msg.requestId) break;
            lastRepeaterResponse = msg.response;
            sendRepeaterBtn.disabled = false;
            document.getElementById("repeaterStatus").textContent =
                `${msg.response.status} ${msg.response.statusText} (${msg.response.duration}ms) • original cancelled • extension-origin`;
            document.getElementById("repeaterStatus").className =
                `response-status ${msg.response.status >= 200 && msg.response.status < 300 ? "success" : "error"}`;
            displayRepeaterResponse(msg.response);
            break;

        case "replacementError":
            if (activeReplacementRequestId !== msg.requestId) break;
            sendRepeaterBtn.disabled = false;
            document.getElementById("repeaterStatus").textContent =
                `Edited request error: ${msg.error}`;
            document.getElementById("repeaterStatus").className =
                "response-status error";
            document.getElementById("repeaterResponseContent").textContent =
                msg.error;
            break;

        case "experimentalPromotionClaimed":
            experimentalPromotionBanner.hidden = !msg.promotion;
            break;

        case "sendToDecoder":
            showDecoderModal(msg.text);
            break;
    }
});

function processNextIntercept() {
    if (interceptQueue.length > 0) {
        const nextRequest = interceptQueue.shift();
        interceptedRequest = nextRequest;
        showInterceptModal(nextRequest);
    }
    updateQueueCounts();
}

function processNextResponseIntercept() {
    if (responseQueue.length > 0) {
        const nextResponse = responseQueue.shift();
        interceptedResponse = nextResponse;
        showResponseInterceptModal(nextResponse);
    }
    updateQueueCounts();
}

function updateQueueCounts() {
    const requestCount = document.getElementById("interceptQueueCount");
    const responseCount = document.getElementById("responseQueueCount");

    if (requestCount) {
        requestCount.textContent =
            interceptQueue.length > 0
                ? `+${interceptQueue.length} pending`
                : "";
        requestCount.classList.toggle("visible", interceptQueue.length > 0);
    }

    if (responseCount) {
        responseCount.textContent =
            responseQueue.length > 0 ? `+${responseQueue.length} pending` : "";
        responseCount.classList.toggle("visible", responseQueue.length > 0);
    }
}

function updateSortIndicators() {
    document.querySelectorAll("#requestTable th[data-column]").forEach((th) => {
        th.classList.remove("sort-asc", "sort-desc");
        if (th.dataset.column === currentSortColumn) {
            th.classList.add(
                currentSortDirection === "asc" ? "sort-asc" : "sort-desc",
            );
        }
    });
}

function sortRequests(requests) {
    if (!currentSortColumn) return requests;

    return [...requests].sort((a, b) => {
        let aVal, bVal;

        switch (currentSortColumn) {
            case "number":
                aVal = a.requestNumber || 0;
                bVal = b.requestNumber || 0;
                break;
            case "method":
                aVal = a.method || "";
                bVal = b.method || "";
                break;
            case "host":
                try {
                    aVal = new URL(a.url).hostname;
                } catch {
                    aVal = "";
                }
                try {
                    bVal = new URL(b.url).hostname;
                } catch {
                    bVal = "";
                }
                break;
            case "url":
                try {
                    aVal = new URL(a.url).pathname;
                } catch {
                    aVal = a.url || "";
                }
                try {
                    bVal = new URL(b.url).pathname;
                } catch {
                    bVal = b.url || "";
                }
                break;
            case "status":
                aVal = a.statusCode || 0;
                bVal = b.statusCode || 0;
                break;
            case "reqSize":
                aVal = calculateRequestSize(a);
                bVal = calculateRequestSize(b);
                break;
            case "resSize":
                aVal = calculateResponseSize(a);
                bVal = calculateResponseSize(b);
                break;
            case "type":
                aVal = a.type || "";
                bVal = b.type || "";
                break;
            default:
                return 0;
        }

        let comparison = 0;
        if (typeof aVal === "string") {
            comparison = aVal.localeCompare(bVal);
        } else {
            comparison = aVal - bVal;
        }

        return currentSortDirection === "asc" ? comparison : -comparison;
    });
}

function renderRequestList() {
    const searchTerm = searchInput.value.toLowerCase();

    // Update domain list options and active badge count
    renderDomainFilterList();
    updateActiveFilterBadge();

    const filteredRequests = requests.filter((req) => {
        // Filter by hidden resource types
        if (hiddenTypes.has(req.type)) {
            return false;
        }

        // Filter by HTTP Method
        const method = (req.method || "GET").toUpperCase();
        if (selectedMethods.size > 0 && !selectedMethods.has(method)) {
            return false;
        }

        // Filter by Status Code
        const status = req.statusCode || 0;
        let statusGroup = "0";
        if (status >= 200 && status < 300) statusGroup = "2xx";
        else if (status >= 300 && status < 400) statusGroup = "3xx";
        else if (status >= 400 && status < 500) statusGroup = "4xx";
        else if (status >= 500) statusGroup = "5xx";
        if (
            selectedStatusGroups.size > 0 &&
            !selectedStatusGroups.has(statusGroup)
        ) {
            return false;
        }

        // Filter by Target Domain
        if (selectedDomains.size > 0) {
            let domain = "";
            try {
                domain = new URL(req.url).hostname;
            } catch {}
            if (!selectedDomains.has(domain)) {
                return false;
            }
        }

        // Filter by Has Security Findings Only
        if (securityOnlyFilter && !req.hasSecurityFindings) {
            return false;
        }

        // Filter by search term
        if (!searchTerm) return true;

        const searchableContent = [
            req.url,
            req.method,
            req.statusCode?.toString(),
            JSON.stringify(req.requestHeaders),
            JSON.stringify(req.responseHeaders),
            req.requestBody,
            req.responseBody,
        ]
            .join(" ")
            .toLowerCase();

        return searchableContent.includes(searchTerm);
    });

    // Sort the filtered requests
    const sortedRequests = sortRequests(filteredRequests);

    requestList.innerHTML = "";

    sortedRequests.forEach((req) => {
        const row = document.createElement("tr");
        row.dataset.requestId = req.id;

        // Apply highlighting rules
        for (const rule of highlightRules) {
            try {
                if (rule.enabled) {
                    let isMatch = false;
                    const type = rule.type || "regex";
                    const pattern = rule.pattern;
                    const target = req.url; // Highlighting only targets URL currently

                    if (!target) continue;

                    switch (type) {
                        case "regex":
                            isMatch = new RegExp(pattern).test(target);
                            break;
                        case "contains":
                            isMatch = target.includes(pattern);
                            break;
                        case "starts_with":
                            isMatch = target.startsWith(pattern);
                            break;
                        case "ends_with":
                            isMatch = target.endsWith(pattern);
                            break;
                        case "exact":
                            isMatch = target === pattern;
                            break;
                    }

                    if (isMatch) {
                        row.style.backgroundColor = rule.color + "40"; // Add 25% opacity
                        break; // Apply first matching rule
                    }
                }
            } catch {
                console.error("Invalid highlight rule pattern:", rule.pattern);
            }
        }

        if (selectedRequest && selectedRequest.id === req.id) {
            row.classList.add("selected");
        }

        if (req.wasModified) {
            row.classList.add("modified-request");
        }

        // Mark requests with security findings
        if (req.hasSecurityFindings || requestFindings.has(req.id)) {
            row.classList.add("request-has-findings");
        }

        const numberCell = document.createElement("td");
        numberCell.textContent = req.requestNumber || "";
        numberCell.className = "request-number";

        const methodCell = document.createElement("td");
        methodCell.textContent = req.method;
        methodCell.className = `method-${req.method}`;

        const hostCell = document.createElement("td");
        try {
            hostCell.textContent = new URL(req.url).hostname;
        } catch {
            hostCell.textContent = "";
        }
        hostCell.title = req.url;

        const urlCell = document.createElement("td");
        urlCell.textContent = new URL(req.url).pathname;
        urlCell.title = req.url;

        const statusCell = document.createElement("td");
        if (req.intercepted) {
            statusCell.textContent = "Intercepted";
            statusCell.className = "status-intercepted";
            statusCell.style.color = "#ff9800";
        } else if (req.replacementState) {
            statusCell.textContent = req.statusLine || req.replacementState;
            statusCell.className =
                req.replacementState === "succeeded"
                    ? "status-modified"
                    : ["failed", "timeout"].includes(req.replacementState)
                      ? "status-error"
                      : "status-intercepted";
            statusCell.title = req.replacementError || req.statusLine || "";
        } else if (req.autoModified) {
            statusCell.textContent = req.statusLine || "Auto-Modified";
            statusCell.className = "status-modified";
            statusCell.style.color = "#9c27b0"; // Purple for auto-modified
            statusCell.title = "Request was automatically modified by a rule";

            // Add icon
            const icon = document.createElement("span");
            icon.textContent = " ⚡";
            statusCell.appendChild(icon);
        } else if (req.statusLine === "Dropped") {
            statusCell.textContent = "Dropped";
            statusCell.className = "status-dropped";
            statusCell.style.color = "#f44336";
        } else if (
            req.statusLine &&
            req.statusLine.startsWith("Modified & Resent")
        ) {
            statusCell.textContent = req.statusCode || "Modified";
            statusCell.className = "status-modified";
            statusCell.style.color = "#9c27b0";
            statusCell.title = "Request was modified and resent";
        } else if (
            req.statusLine &&
            req.statusLine.startsWith("Modification Failed")
        ) {
            statusCell.textContent = "Failed";
            statusCell.className = "status-error";
            statusCell.style.color = "#f44336";
            statusCell.title = req.statusLine;
        } else if (req.statusLine && req.statusLine.startsWith("Resending")) {
            statusCell.textContent = "Resending...";
            statusCell.style.color = "#9c27b0";
        } else if (
            req.statusLine &&
            req.statusLine.startsWith("Forwarded (Unmodified)")
        ) {
            statusCell.textContent = req.statusCode || "Forwarded";
            statusCell.className = req.statusCode
                ? `status-${Math.floor(req.statusCode / 100) * 100}`
                : "";
            statusCell.title = "Request was forwarded without modifications";
        } else if (req.statusLine === "Forwarding" && !req.statusCode) {
            statusCell.textContent = "Forwarding...";
            statusCell.style.color = "#2196F3";
        } else if (req.statusCode !== null && req.statusCode !== undefined) {
            statusCell.textContent = req.statusCode;
            statusCell.className = `status-${Math.floor(req.statusCode / 100) * 100}`;
        } else if (req.completed) {
            statusCell.textContent = "Complete";
        } else {
            statusCell.textContent = "Pending";
        }

        if (["succeeded", "failed", "timeout"].includes(req.replacementState)) {
            const resultButton = document.createElement("button");
            resultButton.type = "button";
            resultButton.className = "replacement-result-btn";
            resultButton.textContent = "View";
            resultButton.title = "Open the edited request result";
            resultButton.setAttribute(
                "aria-label",
                `Open edited request result for ${req.url}`,
            );
            resultButton.addEventListener("click", (event) => {
                event.stopPropagation();
                port.postMessage({
                    type: "getReplacementResult",
                    requestId: req.id,
                });
            });
            statusCell.appendChild(document.createTextNode(" "));
            statusCell.appendChild(resultButton);
        }

        const reqSizeCell = document.createElement("td");
        reqSizeCell.textContent = formatSize(calculateRequestSize(req));

        const resSizeCell = document.createElement("td");
        resSizeCell.textContent = formatSize(calculateResponseSize(req));

        const typeCell = document.createElement("td");
        typeCell.textContent = req.type;

        row.appendChild(numberCell);
        row.appendChild(methodCell);
        row.appendChild(hostCell);
        row.appendChild(urlCell);
        row.appendChild(statusCell);
        row.appendChild(reqSizeCell);
        row.appendChild(resSizeCell);
        row.appendChild(typeCell);

        row.addEventListener("click", () => {
            selectedRequest = req;
            document
                .querySelectorAll("#requestList tr")
                .forEach((r) => r.classList.remove("selected"));
            row.classList.add("selected");
            displayRequestDetails(req);
        });

        requestList.appendChild(row);
    });
}

function displayRequestDetails(request) {
    // Show/hide modified tab based on whether request was modified
    const modifiedTabBtn = document.querySelector(
        '.tab-btn[data-tab="modified"]',
    );
    if (request.wasModified) {
        modifiedTabBtn.style.display = "inline-block";
    } else {
        modifiedTabBtn.style.display = "none";
        // If we're currently on the modified tab, switch to request tab
        if (currentTab === "modified") {
            currentTab = "request";
            document
                .querySelectorAll(".tab-btn")
                .forEach((b) => b.classList.remove("active"));
            document
                .querySelector('.tab-btn[data-tab="request"]')
                .classList.add("active");
            document.getElementById("requestTab").style.display = "flex";
            document.getElementById("modifiedTab").style.display = "none";
            document.getElementById("responseTab").style.display = "none";
            document.getElementById("securityTab").style.display = "none";
        }
    }

    // Show/hide security tab based on whether request has security findings
    displayRequestSecurityFindings(request);

    // Show info note if auto-modified
    const existingNote = document.querySelector(".auto-modified-note");
    if (existingNote) existingNote.remove();

    if (request.autoModified) {
        const note = document.createElement("div");
        note.className = "auto-modified-note";
        note.style.padding = "10px";
        note.style.backgroundColor = "#f3e5f5"; // Light purple
        note.style.borderBottom = "1px solid #e1bee7";
        note.style.color = "#7b1fa2";
        note.style.fontSize = "12px";
        note.innerHTML =
            "<strong>⚡ Info:</strong> This request has been modified.";

        // Insert after tabs
        const tabs = document.querySelector(".tabs");
        tabs.parentNode.insertBefore(note, tabs.nextSibling);
    }

    if (currentTab === "request") {
        const content = formatRequestContent(request, currentRequestView);
        if (currentRequestView === "formatted") {
            renderHighlightedMarkup(requestContent, content);
        } else {
            requestContent.textContent = content;
        }

        // Update active button for request tab
        document.querySelectorAll("#requestTab .view-btn").forEach((btn) => {
            btn.classList.toggle(
                "active",
                btn.dataset.view === currentRequestView,
            );
        });
    } else if (currentTab === "modified") {
        const content = formatModifiedRequestContent(
            request,
            currentModifiedView,
        );
        if (currentModifiedView === "formatted") {
            renderHighlightedMarkup(modifiedContent, content);
        } else {
            modifiedContent.textContent = content;
        }

        // Update active button for modified tab
        document.querySelectorAll("#modifiedTab .view-btn").forEach((btn) => {
            btn.classList.toggle(
                "active",
                btn.dataset.view === currentModifiedView,
            );
        });
    } else if (currentTab === "security") {
        // Security tab content is already rendered by displayRequestSecurityFindings
    } else {
        const result = formatResponseContent(request, currentResponseView);

        // Show/hide Preview button based on HTML content
        if (result.isHTML) {
            responsePreviewBtn.style.display = "inline-block";
        } else {
            responsePreviewBtn.style.display = "none";
            // If currently on preview view and content is not HTML, switch to raw view
            if (currentResponseView === "preview") {
                currentResponseView = "raw";
            }
        }

        if (result.isImage) {
            renderResponseImage(responseContent, result);
        } else if (result.isPreview) {
            renderResponsePreview(responseContent, result);
        } else if (currentResponseView === "formatted") {
            renderHighlightedMarkup(responseContent, result.content);
        } else {
            responseContent.textContent = result.content;
        }

        // Update active button for response tab
        document.querySelectorAll("#responseTab .view-btn").forEach((btn) => {
            btn.classList.toggle(
                "active",
                btn.dataset.view === currentResponseView,
            );
        });
    }
}

function decodeEscapedDisplayText(value) {
    return String(value ?? "")
        .replace(/&#039;/g, "'")
        .replace(/&quot;/g, '"')
        .replace(/&gt;/g, ">")
        .replace(/&lt;/g, "<")
        .replace(/&amp;/g, "&");
}

function renderHighlightedMarkup(container, markup) {
    container.replaceChildren();
    const source = String(markup ?? "");
    const tokenPattern =
        /<span class="(syntax-(?:number|key|string|boolean|null|attr|value|tag))">([\s\S]*?)<\/span>/g;
    let cursor = 0;
    let match;

    while ((match = tokenPattern.exec(source)) !== null) {
        if (match.index > cursor) {
            container.appendChild(
                document.createTextNode(
                    decodeEscapedDisplayText(source.slice(cursor, match.index)),
                ),
            );
        }
        const token = document.createElement("span");
        token.className = match[1];
        token.textContent = decodeEscapedDisplayText(match[2]);
        container.appendChild(token);
        cursor = tokenPattern.lastIndex;
    }

    if (cursor < source.length) {
        container.appendChild(
            document.createTextNode(
                decodeEscapedDisplayText(source.slice(cursor)),
            ),
        );
    }
}

function createResponseHeadersElement(headers) {
    const element = document.createElement("div");
    element.className = "response-headers";
    element.textContent = headers;
    return element;
}

function renderResponseImage(container, result) {
    container.replaceChildren();
    const wrapper = document.createElement("div");
    wrapper.className = "response-image-container";
    const image = document.createElement("img");
    image.src = result.imageSource;
    image.alt = "Response Image";
    image.className = "response-image";
    image.addEventListener("error", () => {
        image.style.display = "none";
        if (image.dataset.errored) return;
        image.dataset.errored = "true";
        const errorElement = document.createElement("div");
        errorElement.style.cssText = "padding: 20px; color: #f44336;";
        errorElement.textContent = "Failed to load image";
        wrapper.appendChild(errorElement);
    });
    wrapper.append(createResponseHeadersElement(result.headers), image);
    container.appendChild(wrapper);
}

function renderResponsePreview(container, result) {
    container.replaceChildren();
    const wrapper = document.createElement("div");
    wrapper.className = "response-preview-container";
    const iframe = document.createElement("iframe");
    iframe.className = "response-preview-iframe";
    iframe.setAttribute("sandbox", "");
    iframe.srcdoc = result.previewDocument;
    wrapper.append(createResponseHeadersElement(result.headers), iframe);
    container.appendChild(wrapper);
}

function highlightSyntax(code, language) {
    if (!code) return "";

    if (language === "json") {
        return code.replace(
            /("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d*)?(?:[eE][+-]?\d+)?)/g,
            (match) => {
                let cls = "syntax-number";
                if (/^"/.test(match)) {
                    if (/:$/.test(match)) {
                        cls = "syntax-key";
                    } else {
                        cls = "syntax-string";
                    }
                } else if (/true|false/.test(match)) {
                    cls = "syntax-boolean";
                } else if (/null/.test(match)) {
                    cls = "syntax-null";
                }
                return '<span class="' + cls + '">' + match + "</span>";
            },
        );
    } else if (language === "xml" || language === "html") {
        return code.replace(
            /(&lt;\/?)([\w:-]+)(.*?)(\/?&gt;)/g,
            (match, start, tag, attrs, end) => {
                const formattedAttrs = attrs.replace(
                    /(\s+)([\w:-]+)(?:(=)(&quot;[^&]*&quot;|"[^"]*"|'[^']*'|[^\s&>]+))?/g,
                    '$1<span class="syntax-attr">$2</span>$3<span class="syntax-value">$4</span>',
                );
                return (
                    start +
                    '<span class="syntax-tag">' +
                    tag +
                    "</span>" +
                    formattedAttrs +
                    end
                );
            },
        );
    }

    return code;
}

function formatRequestContent(request, view) {
    const method = request.originalMethod || request.method;
    const url = request.originalUrl || request.url;
    const headers = request.originalHeaders || request.requestHeaders || {};
    const body =
        request.originalBody === undefined
            ? request.requestBody
            : request.originalBody;
    const bodyEncoding =
        request.originalBodyEncoding ||
        HttpModel.bodyEditorEncoding(request.requestBodyModel);

    if (view === "raw") {
        let raw = `${method} ${url} HTTP/1.1\n`;

        for (const header of HttpModel.normalizeHeaders(headers)) {
            raw += `${header.name}: ${header.value}\n`;
        }

        if (body) {
            raw += `\n${bodyEncoding === "base64" ? "[Base64]\n" : ""}${body}`;
        }

        return raw;
    } else {
        // Formatted view - show headers as-is, format body based on content type
        let formatted = `${escapeHTML(method)} ${escapeHTML(url)} HTTP/1.1\n`;

        for (const header of HttpModel.normalizeHeaders(headers)) {
            formatted += `${escapeHTML(header.name)}: ${escapeHTML(header.value)}\n`;
        }

        if (body) {
            formatted +=
                "\n" +
                (bodyEncoding === "base64"
                    ? `[Base64]\n${escapeHTML(body)}`
                    : formatBody(body, headers));
        }

        return formatted;
    }
}

function formatModifiedRequestContent(request, view) {
    if (!request.wasModified) {
        return "This request was not modified.";
    }

    if (view === "raw") {
        let raw = `${request.modifiedMethod || request.method} ${request.modifiedUrl || request.url} HTTP/1.1\n`;

        const headers = request.modifiedHeaders || request.requestHeaders || {};
        for (const header of HttpModel.normalizeHeaders(headers)) {
            raw += `${header.name}: ${header.value}\n`;
        }

        const body =
            request.modifiedBody === undefined
                ? request.requestBody
                : request.modifiedBody;
        const bodyEncoding =
            request.modifiedBodyEncoding ||
            HttpModel.bodyEditorEncoding(request.requestBodyModel);
        if (body) {
            raw += `\n${bodyEncoding === "base64" ? "[Base64]\n" : ""}${body}`;
        }

        return raw;
    } else {
        // Formatted view - show headers as-is, format body based on content type
        let formatted = `${escapeHTML(request.modifiedMethod || request.method)} ${escapeHTML(request.modifiedUrl || request.url)} HTTP/1.1\n`;

        const headers = request.modifiedHeaders || request.requestHeaders || {};
        for (const header of HttpModel.normalizeHeaders(headers)) {
            formatted += `${escapeHTML(header.name)}: ${escapeHTML(header.value)}\n`;
        }

        const body =
            request.modifiedBody === undefined
                ? request.requestBody
                : request.modifiedBody;
        const bodyEncoding =
            request.modifiedBodyEncoding ||
            HttpModel.bodyEditorEncoding(request.requestBodyModel);
        if (body) {
            formatted +=
                "\n" +
                (bodyEncoding === "base64"
                    ? `[Base64]\n${escapeHTML(body)}`
                    : formatBody(body, headers));
        }

        return formatted;
    }
}

function formatResponseContent(request, view) {
    // Check if response is an image
    const contentType = (
        HttpModel.getHeaderValue(request.responseHeaders, "content-type") || ""
    ).toLowerCase();

    const isImage = contentType.match(
        /^image\/(png|jpe?g|gif|svg\+xml|webp|ico|bmp)/i,
    );
    const isHTMLContent =
        contentType.includes("html") || isHTML(request.responseBody || "");
    const captureNotice = request.truncated
        ? `[Body display truncated: ${formatSize(request.capturedBytes || 0)} of ${formatSize(request.totalBytes || 0)} captured]`
        : "";

    if (isImage && request.responseBody && view === "formatted") {
        if (request.truncated) {
            return {
                isImage: false,
                isHTML: false,
                content:
                    captureNotice +
                    "\nImage preview is disabled for truncated bodies.",
            };
        }
        // For images, display the image in formatted view
        let headers = `${request.statusLine || `HTTP/1.1 ${request.statusCode || "Pending"}`}\n`;
        for (const header of HttpModel.normalizeHeaders(
            request.responseHeaders,
        )) {
            headers += `${header.name}: ${header.value}\n`;
        }

        // Construct the image source
        let imgSrc;
        if (request.responseBody.startsWith("data:")) {
            // Already a data URL
            imgSrc = request.responseBody;
        } else if (
            request.isBase64 ||
            request.responseBody.match(/^[A-Za-z0-9+/=]+$/)
        ) {
            // It's base64 encoded (either marked as such or looks like base64)
            imgSrc = `data:${contentType};base64,${request.responseBody}`;
        } else {
            // Try to encode it
            try {
                imgSrc = `data:${contentType};base64,${safeStringToBase64(request.responseBody)}`;
            } catch (e) {
                // If encoding fails, show error
                return {
                    isImage: false,
                    isHTML: false,
                    content: `Error rendering image: ${escapeHTML(e.message)}`,
                };
            }
        }

        return { isImage: true, isHTML: false, headers, imageSource: imgSrc };
    }

    // Handle HTML preview in iframe
    if (isHTMLContent && request.responseBody && view === "preview") {
        let headers = `${request.statusLine || `HTTP/1.1 ${request.statusCode || "Pending"}`}\n`;
        for (const header of HttpModel.normalizeHeaders(
            request.responseHeaders,
        )) {
            headers += `${header.name}: ${header.value}\n`;
        }

        // Create iframe with sandboxed HTML content
        const previewDocument = `<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:">${request.responseBody}`;
        return {
            isImage: false,
            isHTML: true,
            isPreview: true,
            headers,
            previewDocument,
        };
    }

    if (view === "raw") {
        let raw = `${request.statusLine || `HTTP/1.1 ${request.statusCode || "Pending"}`}\n`;

        for (const header of HttpModel.normalizeHeaders(
            request.responseHeaders,
        )) {
            raw += `${header.name}: ${header.value}\n`;
        }

        if (request.responseBody) {
            raw += `\n${captureNotice ? `${captureNotice}\n` : ""}${request.responseBody}`;
        }

        return { isImage: false, isHTML: isHTMLContent, content: raw };
    } else {
        // Formatted view - show headers as-is, format body based on content type
        let formatted = `${escapeHTML(request.statusLine || `HTTP/1.1 ${request.statusCode || "Pending"}`)}\n`;

        for (const header of HttpModel.normalizeHeaders(
            request.responseHeaders,
        )) {
            formatted += `${escapeHTML(header.name)}: ${escapeHTML(header.value)}\n`;
        }

        if (request.responseBody) {
            formatted +=
                "\n" +
                (captureNotice ? `${escapeHTML(captureNotice)}\n` : "") +
                formatBody(request.responseBody, request.responseHeaders);
        }

        return { isImage: false, isHTML: isHTMLContent, content: formatted };
    }
}

function formatBody(body, headers) {
    if (!body) return "";

    // Get content type from headers (lowercased for case-insensitive matching)
    const contentType = (
        HttpModel.getHeaderValue(headers, "content-type") || ""
    ).toLowerCase();

    // Try to format based on content type or content detection
    if (contentType.includes("json") || isJSON(body)) {
        // Format as JSON
        try {
            const parsed = JSON.parse(body);
            const formatted = JSON.stringify(parsed, null, 2);
            // Escape HTML entities before highlighting to prevent injection
            const escaped = escapeHTML(formatted);
            return highlightSyntax(escaped, "json");
        } catch {
            return escapeHTML(body);
        }
    } else if (contentType.includes("xml") || isXML(body)) {
        // Format as XML
        const formatted = formatXML(body);
        // Simple XML escaping for display before highlighting
        const escaped = escapeHTML(formatted);
        return highlightSyntax(escaped, "xml");
    } else if (contentType.includes("html") || isHTML(body)) {
        // Format as HTML
        const formatted = formatHTML(body);
        const escaped = escapeHTML(formatted);
        return highlightSyntax(escaped, "html");
    } else {
        // Return escaped body for other content types
        return escapeHTML(body);
    }
}

function isXML(str) {
    const trimmed = str.trim();
    return (
        trimmed.startsWith("<?xml") ||
        (trimmed.startsWith("<") && trimmed.endsWith(">"))
    );
}

function isHTML(str) {
    const trimmed = str.trim().toLowerCase();
    return (
        trimmed.includes("<!doctype html") ||
        trimmed.includes("<html") ||
        (trimmed.startsWith("<") &&
            (trimmed.includes("<head") ||
                trimmed.includes("<body") ||
                trimmed.includes("<div")))
    );
}

function formatXML(xml) {
    try {
        let formatted = "";
        let indent = 0;
        const parts = xml.split(/>\s*</);

        for (let i = 0; i < parts.length; i++) {
            let part = parts[i];
            if (i > 0) part = "<" + part;
            if (i < parts.length - 1) part = part + ">";

            // Decrease indent for closing tags
            if (part.match(/^<\/\w/)) indent--;

            formatted += "  ".repeat(Math.max(0, indent)) + part.trim() + "\n";

            // Increase indent for opening tags (not self-closing)
            if (part.match(/^<\w[^>]*[^/]>.*$/)) indent++;
        }

        return formatted.trim();
    } catch {
        return xml;
    }
}

function formatHTML(html) {
    try {
        // Similar to XML but handles HTML specific cases
        let formatted = "";
        let indent = 0;
        const selfClosing = [
            "area",
            "base",
            "br",
            "col",
            "embed",
            "hr",
            "img",
            "input",
            "link",
            "meta",
            "param",
            "source",
            "track",
            "wbr",
        ];

        const parts = html.split(/>\s*</);

        for (let i = 0; i < parts.length; i++) {
            let part = parts[i];
            if (i > 0) part = "<" + part;
            if (i < parts.length - 1) part = part + ">";

            // Check if it's a self-closing tag
            const tagName = part.match(/^<(\w+)/)?.[1]?.toLowerCase();
            const isSelfClosing = selfClosing.includes(tagName);

            // Decrease indent for closing tags
            if (part.match(/^<\/\w/)) indent--;

            formatted += "  ".repeat(Math.max(0, indent)) + part.trim() + "\n";

            // Increase indent for opening tags (not self-closing)
            if (part.match(/^<\w[^>]*[^/]>.*$/) && !isSelfClosing) indent++;
        }

        return formatted.trim();
    } catch {
        return html;
    }
}

function clearRequestDetails() {
    requestContent.textContent = "";
    modifiedContent.textContent = "";
    responseContent.textContent = "";
    selectedRequest = null;

    // Hide modified tab when no request is selected
    const modifiedTabBtn = document.querySelector(
        '.tab-btn[data-tab="modified"]',
    );
    if (modifiedTabBtn) {
        modifiedTabBtn.style.display = "none";
    }

    // Hide and clear security tab when no request is selected
    if (securityTabBtn) {
        securityTabBtn.style.display = "none";
    }
    if (securityTabContent) {
        securityTabContent.innerHTML = `
            <div class="security-no-findings">
                <p>No security findings for this request.</p>
            </div>
        `;
    }
}

function shellEscapeSingleQuote(str) {
    // In POSIX shell, single-quoted strings cannot contain single quotes.
    // The idiom is: end the single quote, add an escaped single quote, restart single quote.
    // e.g. "can't" becomes 'can'\''t'
    return str.replace(/'/g, "'\\''");
}

function buildCurl(method, url, headers, body, bodyEncoding = "text") {
    let curl = `curl -X ${method}`;

    for (const header of HttpModel.normalizeHeaders(headers)) {
        if (!["host", "content-length"].includes(header.name.toLowerCase())) {
            curl += ` \\\n  -H '${shellEscapeSingleQuote(`${header.name}: ${header.value}`)}'`;
        }
    }

    if (bodyEncoding === "base64" && body) {
        curl = `printf '%s' '${shellEscapeSingleQuote(body)}' | base64 --decode | ${curl}`;
        curl += ` \\\n  --data-binary @-`;
    } else if (body && HttpModel.requestMethodAllowsBody(method)) {
        curl += ` \\\n  -d '${shellEscapeSingleQuote(body)}'`;
    }

    curl += ` \\\n  '${shellEscapeSingleQuote(url)}'`;

    return curl;
}

function generateCurl(request) {
    const body =
        request.originalBody === undefined
            ? request.requestBody
            : request.originalBody;
    const bodyEncoding =
        request.originalBodyEncoding ||
        HttpModel.bodyEditorEncoding(request.requestBodyModel);
    return buildCurl(
        request.originalMethod || request.method,
        request.originalUrl || request.url,
        request.originalHeaders || request.requestHeaders,
        body,
        bodyEncoding,
    );
}

function generateModifiedCurl(request) {
    const method = request.modifiedMethod || request.method;
    const url = request.modifiedUrl || request.url;
    const headers = request.modifiedHeaders || request.requestHeaders || {};
    const body =
        request.modifiedBody === undefined
            ? request.requestBody
            : request.modifiedBody;

    return buildCurl(
        method,
        url,
        headers,
        body,
        request.modifiedBodyEncoding ||
            HttpModel.bodyEditorEncoding(request.requestBodyModel),
    );
}

function showInterceptModal(request) {
    interceptHeadersEdited = false;
    interceptBodyEdited = false;
    document.getElementById("interceptMethod").value = request.method;
    document.getElementById("interceptUrl").value = request.url;
    document.getElementById("interceptHeaders").value = formatHeaders(
        request.requestHeaders,
    );
    document.getElementById("interceptHeaders").placeholder = "";
    document.getElementById("interceptHeaders").readOnly =
        request.stage === "onBeforeRequest";

    const bodyModel = request.requestBodyModel || {
        kind: "text",
        text: request.requestBody || "",
        editable: true,
    };
    const bodyEditor = document.getElementById("interceptBody");
    bodyEditor.value = bodyModel.text || "";
    bodyEditor.readOnly = bodyModel.editable === false;
    showInterceptValidationErrors([]);
    document.getElementById("forwardBtn").disabled = false;
    const experimentalMode =
        interceptSettings.modifiedRequestAction === "cancel-and-send";
    document.getElementById("interceptBodyHint").textContent =
        bodyModel.kind === "base64"
            ? `Body is Base64 (${bodyModel.byteLength || 0} bytes). ${experimentalMode ? "Non-native edits cancel the page request and send this copy from the extension." : "Method/body edits are moved to Repeater."}`
            : bodyModel.reason ||
              (experimentalMode
                  ? "Method/body edits cancel the page request and send the edited copy from the extension."
                  : "Method/body edits are moved to Repeater; the page request is forwarded.");
    document.getElementById("interceptBehaviorSummary").textContent =
        experimentalMode
            ? "Experimental mode: header-only edits stay on the browser request. Method/body and late URL edits cancel the page request and send an extension-origin copy; the page will not receive its response."
            : "Safe mode: header changes are applied to the browser request. Method/body and late URL edits forward the original and open an unsent Repeater draft.";
    updateInterceptForwardAction();

    interceptModal.classList.add("show");
}

function updateInterceptForwardAction() {
    const forwardButton = document.getElementById("forwardBtn");
    if (!interceptedRequest) {
        forwardButton.textContent = "Forward";
        forwardButton.disabled = false;
        return;
    }

    const experimentalMode =
        interceptSettings.modifiedRequestAction === "cancel-and-send";
    document.getElementById("interceptBehaviorSummary").textContent =
        experimentalMode
            ? "Experimental mode: header-only edits stay on the browser request. Method/body and late URL edits cancel the page request and send an extension-origin copy; the page will not receive its response."
            : "Safe mode: header changes are applied to the browser request. Method/body and late URL edits forward the original and open an unsent Repeater draft.";

    const modifiedRequest = buildInterceptModifiedRequest();
    const decision = getInterceptDecision(modifiedRequest);
    forwardButton.disabled = decision.action === "reject-edit";

    switch (decision.action) {
        case "cancel-and-send":
            forwardButton.textContent = "Cancel Original & Send Edited";
            break;
        case "create-repeater-draft":
            forwardButton.textContent = "Forward Original & Open Repeater";
            break;
        case "apply-headers":
            forwardButton.textContent = "Forward with Header Changes";
            break;
        case "redirect":
            forwardButton.textContent = "Redirect Request";
            break;
        case "reject-edit":
            forwardButton.textContent = "Fix Request Before Sending";
            showInterceptValidationErrors(decision.validation.errors);
            break;
        default:
            forwardButton.textContent = "Forward";
    }

    if (decision.action !== "reject-edit") {
        showInterceptValidationErrors([]);
    }
}

function closeInterceptModal() {
    if (interceptQueue.length > 0) {
        processNextIntercept();
    } else {
        interceptModal.classList.remove("show");
        interceptedRequest = null;
        interceptHeadersEdited = false;
        interceptBodyEdited = false;
    }
    updateQueueCounts();
}

function formatHeaders(headers) {
    return HttpModel.formatHeaders(headers);
}

function parseHeaders(text) {
    return HttpModel.parseHeaders(text);
}

function calculateRequestSize(request) {
    let size = 0;

    // Calculate URL and method size
    if (request.url) size += request.url.length;
    if (request.method) size += request.method.length;

    // Calculate headers size
    size += HttpModel.headersByteLength(request.requestHeaders);

    // Calculate body size
    if (
        request.requestBodyModel?.byteLength !== null &&
        request.requestBodyModel?.byteLength !== undefined
    ) {
        size += request.requestBodyModel.byteLength;
    } else if (request.requestBody) {
        size += new Blob([request.requestBody]).size;
    }

    return size;
}

function calculateResponseSize(request) {
    let size = 0;

    // Calculate status line size
    if (request.statusCode) {
        size += request.statusCode.toString().length + 15; // Approximate status line
    }

    // Calculate headers size
    size += HttpModel.headersByteLength(request.responseHeaders);

    // Calculate body size
    if (request.responseBody) {
        size += new Blob([request.responseBody]).size;
    }

    return size;
}

function formatSize(bytes) {
    if (bytes === 0) return "-";

    const units = ["B", "KB", "MB", "GB"];
    const i = Math.floor(Math.log(bytes) / Math.log(1024));

    if (i === 0) return bytes + " B";

    return (bytes / 1024 ** i).toFixed(1) + " " + units[i];
}

function showRepeaterModal(request) {
    activeReplacementRequestId = null;
    activeRepeaterRequestId = null;
    document.getElementById("repeaterMethod").value = request.method;
    document.getElementById("repeaterUrl").value = request.url;
    document.getElementById("repeaterHeaders").value = formatHeaders(
        request.requestHeaders,
    );
    const bodyModel = request.requestBodyModel || {
        kind: "text",
        text: request.requestBody || "",
        editable: true,
    };
    setRepeaterBody(
        bodyModel.text,
        HttpModel.bodyEditorEncoding(bodyModel),
        bodyModel.editable,
        bodyModel.reason,
        bodyModel.replayable !== false,
    );

    document.getElementById("repeaterStatus").textContent = "No response yet";
    document.getElementById("repeaterStatus").className = "response-status";
    document.getElementById("repeaterResponseContent").textContent = "";
    lastRepeaterResponse = null;
    sendRepeaterBtn.disabled = false;

    repeaterModal.classList.add("show");
}

function showModifiedRepeaterModal(request) {
    activeReplacementRequestId = null;
    activeRepeaterRequestId = null;
    const method = request.modifiedMethod || request.method;
    const url = request.modifiedUrl || request.url;
    const headers = request.modifiedHeaders || request.requestHeaders || {};
    const body =
        request.modifiedBody === undefined
            ? request.requestBody
            : request.modifiedBody;

    document.getElementById("repeaterMethod").value = method;
    document.getElementById("repeaterUrl").value = url;
    document.getElementById("repeaterHeaders").value = formatHeaders(headers);
    setRepeaterBody(
        body,
        request.modifiedBodyEncoding || "text",
        true,
        "This is an explicit extension-origin Repeater request.",
    );

    document.getElementById("repeaterStatus").textContent = "No response yet";
    document.getElementById("repeaterStatus").className = "response-status";
    document.getElementById("repeaterResponseContent").textContent = "";
    lastRepeaterResponse = null;
    sendRepeaterBtn.disabled = false;

    repeaterModal.classList.add("show");
}

function setRepeaterBody(
    body,
    encoding = "text",
    editable = true,
    reason = "",
    replayable = true,
) {
    repeaterBodyEncoding = encoding;
    repeaterBodyReplayable = replayable;
    const editor = document.getElementById("repeaterBody");
    editor.value = body ?? "";
    editor.readOnly = editable === false;
    document.getElementById("repeaterBodyHint").textContent =
        encoding === "base64"
            ? `${reason || "Binary body is represented as Base64."} Repeater requests originate from the extension.`
            : `${reason || ""} Repeater requests originate from the extension.`.trim();
}

function showRepeaterDraft(requestData) {
    activeReplacementRequestId = null;
    activeRepeaterRequestId = null;
    document.getElementById("repeaterMethod").value = requestData.method;
    document.getElementById("repeaterUrl").value = requestData.url;
    document.getElementById("repeaterHeaders").value = formatHeaders(
        requestData.headers,
    );
    setRepeaterBody(
        requestData.body,
        requestData.bodyEncoding || "text",
        requestData.bodyEditable !== false,
        "Edits from interception were moved here; click Send Request to transmit the copy.",
        requestData.bodyReplayable !== false,
    );
    document.getElementById("repeaterStatus").textContent =
        "Draft ready — original page request was forwarded";
    document.getElementById("repeaterStatus").className = "response-status";
    document.getElementById("repeaterResponseContent").textContent = "";
    lastRepeaterResponse = null;
    sendRepeaterBtn.disabled = false;
    repeaterModal.classList.add("show");
}

function showReplacementRequest(requestId, requestData, statusText) {
    activeReplacementRequestId = requestId;
    activeRepeaterRequestId = null;
    document.getElementById("repeaterMethod").value = requestData.method;
    document.getElementById("repeaterUrl").value = requestData.url;
    document.getElementById("repeaterHeaders").value = formatHeaders(
        requestData.headers,
    );
    setRepeaterBody(
        requestData.body,
        requestData.bodyEncoding || "text",
        requestData.bodyEditable !== false,
        "The page request is being cancelled; this edited copy is sent automatically from the extension.",
    );
    document.getElementById("repeaterStatus").textContent = statusText;
    document.getElementById("repeaterStatus").className = "response-status";
    document.getElementById("repeaterResponseContent").textContent = "";
    lastRepeaterResponse = null;
    sendRepeaterBtn.disabled = true;
    repeaterModal.classList.add("show");
}

function showStoredReplacementResult(requestId, requestData, result) {
    showReplacementRequest(
        requestId,
        requestData,
        result
            ? "Loading saved edited request result..."
            : "Edited request result is no longer retained.",
    );

    if (!result) {
        document.getElementById("repeaterStatus").className =
            "response-status error";
        document.getElementById("repeaterResponseContent").textContent =
            "The bounded result cache evicted this response. The request metadata remains available.";
        return;
    }

    if (result.state === "succeeded" && result.response) {
        lastRepeaterResponse = result.response;
        document.getElementById("repeaterStatus").textContent =
            `${result.response.status} ${result.response.statusText} (${result.response.duration}ms) • saved edited result • extension-origin`;
        document.getElementById("repeaterStatus").className =
            `response-status ${result.response.status >= 200 && result.response.status < 300 ? "success" : "error"}`;
        displayRepeaterResponse(result.response);
        return;
    }

    document.getElementById("repeaterStatus").textContent =
        `Edited request ${result.state}: ${result.error || "Unknown error"}`;
    document.getElementById("repeaterStatus").className =
        "response-status error";
    document.getElementById("repeaterResponseContent").textContent =
        result.error || "Unknown edited request error";
}

function sendRepeaterRequest() {
    const method = document.getElementById("repeaterMethod").value;
    const url = document.getElementById("repeaterUrl").value;
    const headersText = document.getElementById("repeaterHeaders").value;
    const body = document.getElementById("repeaterBody").value;

    const headers = parseHeaders(headersText);
    const requestData = {
        method,
        url,
        headers,
        headersText,
        body,
        bodyEncoding: repeaterBodyEncoding,
        bodyReplayable: repeaterBodyReplayable,
    };
    const validation = RequestInterception.validateEditedRequest(requestData, {
        maxBodyBytes: MAX_REPLAY_BODY_BYTES,
    });
    if (!validation.valid) {
        document.getElementById("repeaterStatus").textContent =
            `Validation error: ${validation.errors.map((error) => error.message).join(" ")}`;
        document.getElementById("repeaterStatus").className =
            "response-status error";
        sendRepeaterBtn.disabled = false;
        return;
    }

    activeReplacementRequestId = null;
    activeRepeaterRequestId = `repeater-${++repeaterRequestCounter}`;

    document.getElementById("repeaterStatus").textContent =
        "Sending request...";
    document.getElementById("repeaterStatus").className = "response-status";
    sendRepeaterBtn.disabled = true;

    port.postMessage({
        type: "sendRepeaterRequest",
        requestId: activeRepeaterRequestId,
        requestData,
    });
}

function displayRepeaterResponse(response) {
    const content = document.getElementById("repeaterResponseContent");
    const truncationNotice = response.truncated
        ? `[Body truncated: ${formatSize(response.capturedBytes || 0)} of ${formatSize(response.totalBytes || 0)}]\n`
        : "";

    switch (currentRepeaterTab) {
        case "headers":
            content.textContent = formatHeaders(response.headers);
            break;
        case "body":
            if (response.isBase64) {
                content.textContent = `${truncationNotice}[Binary response shown as Base64]\n${response.body}`;
            } else if (isJSON(response.body)) {
                try {
                    content.textContent =
                        truncationNotice +
                        JSON.stringify(JSON.parse(response.body), null, 2);
                } catch {
                    content.textContent = truncationNotice + response.body;
                }
            } else {
                content.textContent = truncationNotice + response.body;
            }
            break;
        case "raw": {
            let raw = `HTTP/1.1 ${response.status} ${response.statusText}\n`;
            raw += formatHeaders(response.headers);
            raw +=
                "\n\n" +
                truncationNotice +
                (response.isBase64 ? "[Base64]\n" : "") +
                response.body;
            content.textContent = raw;
            break;
        }
    }
}

function isJSON(str) {
    try {
        JSON.parse(str);
        return true;
    } catch {
        return false;
    }
}

function highlightContent(elementId, searchTerm, countElement) {
    const element = document.getElementById(elementId);
    if (!element) return;

    const originalText = element.textContent;

    if (!searchTerm) {
        element.textContent = originalText;
        if (countElement) countElement.textContent = "";
        return;
    }

    try {
        const regex = new RegExp(escapeRegExp(searchTerm), "gi");
        const matches = originalText.match(regex);
        const matchCount = matches ? matches.length : 0;

        if (matchCount > 0) {
            const fragment = document.createDocumentFragment();
            let cursor = 0;
            for (const match of originalText.matchAll(regex)) {
                fragment.appendChild(
                    document.createTextNode(
                        originalText.slice(cursor, match.index),
                    ),
                );
                const mark = document.createElement("mark");
                mark.textContent = match[0];
                fragment.appendChild(mark);
                cursor = match.index + match[0].length;
            }
            fragment.appendChild(
                document.createTextNode(originalText.slice(cursor)),
            );
            element.replaceChildren(fragment);
            if (countElement)
                countElement.textContent = `${matchCount} match${matchCount === 1 ? "" : "es"}`;
        } else {
            element.textContent = originalText;
            if (countElement) countElement.textContent = "No matches";
        }
    } catch {
        element.textContent = originalText;
        if (countElement) countElement.textContent = "";
    }
}

function escapeRegExp(string) {
    return string.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

// Add search functionality for intercept and repeater modals
function setupModalSearch() {
    // Intercept modal search
    const interceptSearchInput = document.getElementById(
        "interceptSearchInput",
    );
    const interceptSearchCount = document.getElementById(
        "interceptSearchCount",
    );

    if (interceptSearchInput) {
        interceptSearchInput.addEventListener("input", () => {
            const searchTerm = interceptSearchInput.value;
            const content =
                document.getElementById("interceptMethod").value +
                "\n" +
                document.getElementById("interceptUrl").value +
                "\n" +
                document.getElementById("interceptHeaders").value +
                "\n" +
                document.getElementById("interceptBody").value;

            if (searchTerm) {
                const regex = new RegExp(`(${escapeRegExp(searchTerm)})`, "gi");
                const matches = content.match(regex);
                const matchCount = matches ? matches.length : 0;
                interceptSearchCount.textContent =
                    matchCount > 0
                        ? `${matchCount} match${matchCount === 1 ? "" : "es"}`
                        : "No matches";

                // Highlight in textareas
                highlightTextarea("interceptHeaders", searchTerm);
                highlightTextarea("interceptBody", searchTerm);
            } else {
                interceptSearchCount.textContent = "";
            }
        });
    }

    // Repeater request search
    const repeaterRequestSearchInput = document.getElementById(
        "repeaterRequestSearchInput",
    );
    const repeaterRequestSearchCount = document.getElementById(
        "repeaterRequestSearchCount",
    );

    if (repeaterRequestSearchInput) {
        repeaterRequestSearchInput.addEventListener("input", () => {
            const searchTerm = repeaterRequestSearchInput.value;
            highlightTextarea("repeaterHeaders", searchTerm);
            highlightTextarea("repeaterBody", searchTerm);

            if (searchTerm) {
                const content =
                    document.getElementById("repeaterMethod").value +
                    "\n" +
                    document.getElementById("repeaterUrl").value +
                    "\n" +
                    document.getElementById("repeaterHeaders").value +
                    "\n" +
                    document.getElementById("repeaterBody").value;

                const regex = new RegExp(`(${escapeRegExp(searchTerm)})`, "gi");
                const matches = content.match(regex);
                const matchCount = matches ? matches.length : 0;
                repeaterRequestSearchCount.textContent =
                    matchCount > 0
                        ? `${matchCount} match${matchCount === 1 ? "" : "es"}`
                        : "No matches";
            } else {
                repeaterRequestSearchCount.textContent = "";
            }
        });
    }

    // Repeater response search
    const repeaterResponseSearchInput = document.getElementById(
        "repeaterResponseSearchInput",
    );
    const repeaterResponseSearchCount = document.getElementById(
        "repeaterResponseSearchCount",
    );

    if (repeaterResponseSearchInput) {
        repeaterResponseSearchInput.addEventListener("input", () => {
            const searchTerm = repeaterResponseSearchInput.value;
            highlightContent(
                "repeaterResponseContent",
                searchTerm,
                repeaterResponseSearchCount,
            );
        });
    }
}

function highlightTextarea(textareaId, searchTerm) {
    const textarea = document.getElementById(textareaId);
    if (!textarea) return;

    // For textareas, we can't use HTML markup, so we'll just select the first match
    if (
        searchTerm &&
        textarea.value.toLowerCase().includes(searchTerm.toLowerCase())
    ) {
        const startIndex = textarea.value
            .toLowerCase()
            .indexOf(searchTerm.toLowerCase());
        textarea.setSelectionRange(startIndex, startIndex + searchTerm.length);
    }
}

// Initialize modal search when DOM is ready
setTimeout(setupModalSearch, 100);

// Intercept Settings Functions
let promotionHighlightTimeout = null;
let promotionFocusFrame = null;

function clearExperimentalSettingsHighlight() {
    if (promotionFocusFrame !== null) {
        cancelAnimationFrame(promotionFocusFrame);
        promotionFocusFrame = null;
    }
    if (promotionHighlightTimeout !== null) {
        clearTimeout(promotionHighlightTimeout);
        promotionHighlightTimeout = null;
    }
    modifiedRequestActionSection.classList.remove("promotion-target-highlight");
}

function focusExperimentalSettings() {
    promotionFocusFrame = null;
    clearExperimentalSettingsHighlight();
    const reducedMotion =
        typeof matchMedia === "function" &&
        matchMedia("(prefers-reduced-motion: reduce)").matches;

    modifiedRequestActionSection.scrollIntoView({
        behavior: reducedMotion ? "auto" : "smooth",
        block: "center",
    });
    modifiedRequestActionSection.classList.add("promotion-target-highlight");
    document
        .getElementById("modifiedRequestCancelAndSend")
        .focus({ preventScroll: true });
    promotionHighlightTimeout = setTimeout(
        clearExperimentalSettingsHighlight,
        2200,
    );
}

function showInterceptSettingsModal(options = {}) {
    updateInterceptSettingsUI();
    interceptSettingsModal.classList.add("show");
    if (options.focusModifiedRequestAction) {
        promotionFocusFrame = requestAnimationFrame(focusExperimentalSettings);
    }
}

function closeInterceptSettingsModal() {
    clearExperimentalSettingsHighlight();
    interceptSettingsModal.classList.remove("show");
}

function updateInterceptSettingsUI() {
    interceptSettings.modifiedRequestAction =
        RequestInterception.normalizeModifiedRequestAction(
            interceptSettings.modifiedRequestAction,
        );
    // Update method checkboxes
    const allMethods = [
        "GET",
        "POST",
        "PUT",
        "PATCH",
        "DELETE",
        "HEAD",
        "OPTIONS",
    ];
    allMethods.forEach((method) => {
        const checkbox = document.getElementById(`intercept${method}`);
        if (checkbox) {
            if (method === "GET") {
                checkbox.checked = interceptSettings.includeGET;
            } else {
                checkbox.checked = interceptSettings.methods.includes(method);
            }
        }
    });

    // Update GET warning visibility
    const getWarning = document.getElementById("getWarning");
    getWarning.style.display = interceptSettings.includeGET ? "block" : "none";

    // Update URL patterns
    document.getElementById("includePatterns").value =
        interceptSettings.urlPatterns.join("\n");
    document.getElementById("excludePatterns").value =
        interceptSettings.excludePatterns.join("\n");

    // Update file extensions
    document.getElementById("excludeExtensions").value =
        interceptSettings.excludeExtensions.join(", ");

    // Update response interception
    document.getElementById("interceptResponses").checked =
        interceptSettings.interceptResponses;
    const responseWarning = document.getElementById("responseWarning");
    responseWarning.style.display = interceptSettings.interceptResponses
        ? "block"
        : "none";

    document.getElementById("modifiedRequestRepeaterDraft").checked =
        interceptSettings.modifiedRequestAction === "repeater-draft";
    document.getElementById("modifiedRequestCancelAndSend").checked =
        interceptSettings.modifiedRequestAction === "cancel-and-send";
    document.getElementById("experimentalModeAcknowledged").checked =
        interceptSettings.modifiedRequestAction === "cancel-and-send";
    document.getElementById("useEarlyInterception").checked =
        interceptSettings.modifiedRequestAction === "cancel-and-send"
            ? false
            : Boolean(interceptSettings.useEarlyInterception);
    delete document.getElementById("useEarlyInterception").dataset
        .previousChecked;
    const earlyInterceptionWarning = document.getElementById(
        "earlyInterceptionWarning",
    );
    earlyInterceptionWarning.style.display =
        interceptSettings.modifiedRequestAction !== "cancel-and-send" &&
        interceptSettings.useEarlyInterception
            ? "block"
            : "none";
    updateExperimentalSettingControls();

    // Update Scope settings
    document.getElementById("enableScope").checked =
        interceptSettings.scopeEnabled || false;
    document.getElementById("scopePatterns").value = (
        interceptSettings.scopePatterns || []
    ).join("\n");
    document.getElementById("scopeExcludePatterns").value = (
        interceptSettings.scopeExcludePatterns || []
    ).join("\n");
}

function saveInterceptSettings() {
    // Collect method settings
    const methods = [];
    let includeGET = false;

    const allMethods = [
        "GET",
        "POST",
        "PUT",
        "PATCH",
        "DELETE",
        "HEAD",
        "OPTIONS",
    ];
    allMethods.forEach((method) => {
        const checkbox = document.getElementById(`intercept${method}`);
        if (checkbox && checkbox.checked) {
            if (method === "GET") {
                includeGET = true;
            } else {
                methods.push(method);
            }
        }
    });

    // Collect URL patterns
    const includePatterns = document
        .getElementById("includePatterns")
        .value.split("\n")
        .map((p) => p.trim())
        .filter((p) => p.length > 0);

    const excludePatterns = document
        .getElementById("excludePatterns")
        .value.split("\n")
        .map((p) => p.trim())
        .filter((p) => p.length > 0);

    // Collect Scope settings
    const scopeEnabled = document.getElementById("enableScope").checked;
    const scopePatterns = document
        .getElementById("scopePatterns")
        .value.split("\n")
        .map((p) => p.trim())
        .filter((p) => p.length > 0);
    const scopeExcludePatterns = document
        .getElementById("scopeExcludePatterns")
        .value.split("\n")
        .map((p) => p.trim())
        .filter((p) => p.length > 0);

    // Collect file extensions
    const excludeExtensions = document
        .getElementById("excludeExtensions")
        .value.split(",")
        .map((ext) => ext.trim())
        .filter((ext) => ext.length > 0);

    // Get response interception setting
    const interceptResponses =
        document.getElementById("interceptResponses").checked;

    // Get early interception setting
    const modifiedRequestAction = document.getElementById(
        "modifiedRequestCancelAndSend",
    ).checked
        ? "cancel-and-send"
        : "repeater-draft";
    const useEarlyInterception =
        modifiedRequestAction === "cancel-and-send"
            ? false
            : document.getElementById("useEarlyInterception").checked;

    // Validate regex patterns
    const invalidPatterns = [];
    [
        ...includePatterns,
        ...excludePatterns,
        ...scopePatterns,
        ...scopeExcludePatterns,
    ].forEach((pattern) => {
        try {
            new RegExp(pattern);
        } catch {
            invalidPatterns.push(pattern);
        }
    });

    if (invalidPatterns.length > 0) {
        alert(
            `Invalid regex patterns found:\n${invalidPatterns.join("\n")}\n\nPlease fix these patterns before saving.`,
        );
        return;
    }

    const acknowledgement = document.getElementById(
        "experimentalModeAcknowledged",
    );
    if (
        modifiedRequestAction === "cancel-and-send" &&
        !acknowledgement.checked
    ) {
        document.getElementById("experimentalModeSaveError").hidden = false;
        acknowledgement.setAttribute("aria-invalid", "true");
        acknowledgement.scrollIntoView({ block: "center" });
        acknowledgement.focus({ preventScroll: true });
        return;
    }

    // Update settings
    const newSettings = {
        methods: methods,
        includeGET: includeGET,
        urlPatterns: includePatterns,
        excludePatterns: excludePatterns,
        excludeExtensions: excludeExtensions,
        interceptResponses: interceptResponses,
        useEarlyInterception: useEarlyInterception,
        modifiedRequestAction: modifiedRequestAction,
        scopeEnabled: scopeEnabled,
        scopePatterns: scopePatterns,
        scopeExcludePatterns: scopeExcludePatterns,
    };

    port.postMessage({
        type: "updateInterceptSettings",
        settings: newSettings,
    });

    closeInterceptSettingsModal();
}

function resetInterceptSettings() {
    const defaultSettings = {
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

    port.postMessage({
        type: "updateInterceptSettings",
        settings: defaultSettings,
    });

    closeInterceptSettingsModal();
}

function showResponseInterceptModal(response) {
    responseHeadersEdited = false;
    responseBodyEdited = false;
    forwardResponseBtn.disabled = false;
    showResponseInterceptValidationErrors([]);
    document.getElementById("responseStatusCode").value =
        response.statusCode || 200;
    document.getElementById("responseStatusText").value =
        response.statusLine || "OK";
    document.getElementById("responseHeaders").value = formatHeaders(
        response.responseHeaders,
    );
    document.getElementById("responseBody").value = response.responseBody || "";

    const isHeaderStage = response.stage === "responseHeaders";
    document.getElementById("responseHeaders").readOnly = !isHeaderStage;
    document.getElementById("responseBody").readOnly = isHeaderStage;
    document.getElementById("dropResponseBtn").textContent = isHeaderStage
        ? "Drop Response"
        : "Return Empty Body";
    document.getElementById("responseStageHint").textContent = isHeaderStage
        ? "Headers can be edited now. Content-Length is removed before the body stage so later body edits remain valid."
        : response.isBase64
          ? "Binary or unknown response bytes are represented as Base64. Headers and status are already fixed; invalid Base64 is rejected without releasing the response."
          : "The body can be edited now. Headers and status are already fixed; “Return Empty Body” cannot cancel the response headers.";

    responseInterceptModal.classList.add("show");
}

function closeResponseInterceptModal() {
    if (responseQueue.length > 0) {
        processNextResponseIntercept();
    } else {
        responseInterceptModal.classList.remove("show");
        interceptedResponse = null;
        responseHeadersEdited = false;
        responseBodyEdited = false;
        forwardResponseBtn.disabled = false;
        showResponseInterceptValidationErrors([]);
    }
    updateQueueCounts();
}

function showResponseInterceptValidationErrors(errors = []) {
    const errorElement = document.getElementById(
        "responseInterceptValidationError",
    );
    errorElement.textContent = errors.map((error) => error.message).join("\n");
    errorElement.hidden = errors.length === 0;
}

// Decoder Elements
const decoderBtn = document.getElementById("decoderBtn");
const decoderModal = document.getElementById("decoderModal");
const closeDecoderBtn = document.getElementById("closeDecoderBtn");
const decoderInput = document.getElementById("decoderInput");
const decoderOutput = document.getElementById("decoderOutput");
const decoderOperation = document.getElementById("decoderOperation");
const decoderEncodeBtn = document.getElementById("decoderEncodeBtn");
const decoderDecodeBtn = document.getElementById("decoderDecodeBtn");
const decoderClearInputBtn = document.getElementById("decoderClearInputBtn");
const decoderClearOutputBtn = document.getElementById("decoderClearOutputBtn");
const decoderCopyBtn = document.getElementById("decoderCopyBtn");
const decoderSwapBtn = document.getElementById("decoderSwapBtn");

// Decoder Event Listeners
decoderBtn.addEventListener("click", () => {
    showDecoderModal();
});

closeDecoderBtn.addEventListener("click", () => {
    decoderModal.classList.remove("show");
});

document.getElementById("sendToDecoderBtn").addEventListener("click", () => {
    if (selectedRequest) {
        const content = formatRequestContent(selectedRequest, "raw");
        showDecoderModal(content);
    }
});

document
    .getElementById("modifiedSendToDecoderBtn")
    .addEventListener("click", () => {
        if (selectedRequest && selectedRequest.wasModified) {
            const content = formatModifiedRequestContent(
                selectedRequest,
                "raw",
            );
            showDecoderModal(content);
        }
    });

decoderClearInputBtn.addEventListener("click", () => {
    decoderInput.value = "";
});

decoderClearOutputBtn.addEventListener("click", () => {
    decoderOutput.value = "";
});

decoderCopyBtn.addEventListener("click", () => {
    navigator.clipboard.writeText(decoderOutput.value).then(() => {
        const originalText = decoderCopyBtn.textContent;
        decoderCopyBtn.textContent = "Copied!";
        setTimeout(() => {
            decoderCopyBtn.textContent = originalText;
        }, 2000);
    });
});

decoderSwapBtn.addEventListener("click", () => {
    const input = decoderInput.value;
    const output = decoderOutput.value;
    decoderInput.value = output;
    decoderOutput.value = input;
});

decoderEncodeBtn.addEventListener("click", () => {
    performEncoding();
});

decoderDecodeBtn.addEventListener("click", () => {
    performDecoding();
});

function showDecoderModal(initialText = "") {
    if (initialText) {
        decoderInput.value = initialText;
    }
    decoderModal.classList.add("show");
}

function performEncoding() {
    const input = decoderInput.value;
    const operation = decoderOperation.value;
    let output = "";

    try {
        switch (operation) {
            case "url":
                output = encodeURIComponent(input);
                break;
            case "base64":
                output = btoa(input);
                break;
            case "hex":
                output = stringToHex(input);
                break;
            case "html":
                output = escapeHTML(input);
                break;
        }
        decoderOutput.value = output;
    } catch (e) {
        decoderOutput.value = `Error encoding: ${e.message}`;
    }
}

function performDecoding() {
    const input = decoderInput.value;
    const operation = decoderOperation.value;
    let output = "";

    try {
        switch (operation) {
            case "url":
                output = decodeURIComponent(input);
                break;
            case "base64":
                output = atob(input);
                break;
            case "hex":
                output = hexToString(input);
                break;
            case "html":
                output = unescapeHTML(input);
                break;
            case "jwt":
                output = decodeJWT(input);
                break;
        }
        decoderOutput.value = output;
    } catch (e) {
        decoderOutput.value = `Error decoding: ${e.message}`;
    }
}

function decodeJWT(token) {
    try {
        const parts = token.split(".");
        if (parts.length !== 3) {
            throw new Error(
                "Invalid JWT format. Expected 3 parts separated by dots.",
            );
        }

        const header = JSON.parse(
            atob(parts[0].replace(/-/g, "+").replace(/_/g, "/")),
        );
        const payload = JSON.parse(
            atob(parts[1].replace(/-/g, "+").replace(/_/g, "/")),
        );

        let output = "=== Header ===\n";
        output += JSON.stringify(header, null, 2);
        output += "\n\n=== Payload ===\n";
        output += JSON.stringify(payload, null, 2);

        if (payload.exp) {
            const expDate = new Date(payload.exp * 1000);
            output += `\n\nExpires: ${expDate.toLocaleString()}`;
            const now = new Date();
            if (now > expDate) {
                output += " (Expired)";
            } else {
                output += " (Valid)";
            }
        }

        if (payload.iat) {
            const iatDate = new Date(payload.iat * 1000);
            output += `\nIssued At: ${iatDate.toLocaleString()}`;
        }

        output += "\n\n=== Signature ===\n";
        output += parts[2];

        return output;
    } catch (e) {
        throw new Error("Failed to decode JWT: " + e.message);
    }
}

function stringToHex(str) {
    let hex = "";
    for (let i = 0; i < str.length; i++) {
        hex += "" + str.charCodeAt(i).toString(16).padStart(2, "0");
    }
    return hex;
}

function hexToString(hex) {
    let str = "";
    for (let i = 0; i < hex.length; i += 2) {
        str += String.fromCharCode(parseInt(hex.substr(i, 2), 16));
    }
    return str;
}

function escapeHTML(str) {
    return String(str ?? "")
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

function normalizeFindingSeverity(value, fallback = "info") {
    const allowed = new Set(["critical", "high", "medium", "low", "info"]);
    return allowed.has(value) ? value : fallback;
}

function unescapeHTML(str) {
    return str
        .replace(/&#039;/g, "'")
        .replace(/&quot;/g, '"')
        .replace(/&gt;/g, ">")
        .replace(/&lt;/g, "<")
        .replace(/&amp;/g, "&");
}

function isSafeHttpUrl(url) {
    if (!url || typeof url !== "string") return false;
    try {
        const parsed = new URL(url);
        return parsed.protocol === "http:" || parsed.protocol === "https:";
    } catch {
        return false;
    }
}

function safeUint8ArrayToBase64(uint8Array) {
    if (!uint8Array) return "";
    try {
        let binary = "";
        const chunkSize = 8192;
        const len = uint8Array.length;
        for (let i = 0; i < len; i += chunkSize) {
            const chunk = uint8Array.subarray(i, i + chunkSize);
            binary += String.fromCharCode.apply(null, chunk);
        }
        return btoa(binary);
    } catch (e) {
        console.error("Failed to encode Uint8Array to Base64:", e);
        return "";
    }
}

function safeStringToBase64(str) {
    if (!str) return "";
    try {
        const bytes = new TextEncoder().encode(str);
        return safeUint8ArrayToBase64(bytes);
    } catch (e) {
        console.error("Failed to encode string to Base64:", e);
        return "";
    }
}
