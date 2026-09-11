(function initializeLibraryScannerCore(root, factory) {
  const core = factory();

  root.EnhancedNetworkTab = root.EnhancedNetworkTab || {};
  root.EnhancedNetworkTab.LibraryScannerCore = core;

  if (typeof module === "object" && module.exports) {
    module.exports = core;
  }
})(
  typeof globalThis === "undefined" ? this : globalThis,
  function createLibraryScannerCore() {
    const QUALIFIER_ALIASES = {
      a: "alpha",
      b: "beta",
      cr: "rc",
      m: "milestone",
    };

    const QUALIFIER_ORDER = {
      dev: -60,
      snapshot: -60,
      canary: -50,
      next: -40,
      alpha: -30,
      milestone: -25,
      beta: -20,
      pre: -15,
      preview: -15,
      rc: -10,
    };

    const RELEASE_QUALIFIERS = new Set(["final", "ga", "release", "stable"]);

    function normalizeVersionString(version) {
      if (typeof version !== "string" && typeof version !== "number") {
        return null;
      }

      const normalized = String(version)
        .trim()
        .toLowerCase()
        .replace(/^v(?=\d)/, "");
      return normalized || null;
    }

    function tokenizeVersion(version) {
      const normalized = normalizeVersionString(version);
      if (!normalized) return null;

      const expanded = normalized
        .replace(/([0-9])([a-z])/g, "$1.$2")
        .replace(/([a-z])([0-9])/g, "$1.$2");

      const tokens = expanded
        .split(/[^0-9a-z]+/)
        .filter(Boolean)
        .flatMap((part) => part.match(/[0-9]+|[a-z]+/g) || [])
        .map((token) => {
          if (/^\d+$/.test(token)) return Number(token);
          return QUALIFIER_ALIASES[token] || token;
        });

      if (tokens.length === 0 || typeof tokens[0] !== "number") {
        return null;
      }

      const core = [];
      const prerelease = [];
      let inPrerelease = false;

      for (const token of tokens) {
        if (!inPrerelease && typeof token === "number") {
          core.push(token);
          continue;
        }

        inPrerelease = true;
        prerelease.push(token);
      }

      if (prerelease.length > 0 && RELEASE_QUALIFIERS.has(prerelease[0])) {
        prerelease.length = 0;
      }

      return {
        raw: normalized,
        core,
        prerelease,
        coreSegmentCount: core.length,
      };
    }

    function compareCore(leftCore, rightCore) {
      const length = Math.max(leftCore.length, rightCore.length);

      for (let index = 0; index < length; index += 1) {
        const left = leftCore[index] ?? 0;
        const right = rightCore[index] ?? 0;

        if (left < right) return -1;
        if (left > right) return 1;
      }

      return 0;
    }

    function compareQualifier(left, right) {
      if (left === right) return 0;

      if (typeof left === "number" && typeof right === "number") {
        return left < right ? -1 : 1;
      }

      if (typeof left === "number") return -1;
      if (typeof right === "number") return 1;

      const leftRank = QUALIFIER_ORDER[left];
      const rightRank = QUALIFIER_ORDER[right];

      if (leftRank !== undefined || rightRank !== undefined) {
        const normalizedLeftRank = leftRank ?? -5;
        const normalizedRightRank = rightRank ?? -5;

        if (normalizedLeftRank !== normalizedRightRank) {
          return normalizedLeftRank < normalizedRightRank ? -1 : 1;
        }
      }

      return left < right ? -1 : 1;
    }

    function comparePrerelease(leftPrerelease, rightPrerelease) {
      if (leftPrerelease.length === 0 && rightPrerelease.length === 0) return 0;
      if (leftPrerelease.length === 0) return 1;
      if (rightPrerelease.length === 0) return -1;

      const length = Math.max(leftPrerelease.length, rightPrerelease.length);

      for (let index = 0; index < length; index += 1) {
        const left = leftPrerelease[index];
        const right = rightPrerelease[index];

        if (left === undefined) {
          if (typeof right === "number" && right === 0) continue;
          return -1;
        }

        if (right === undefined) {
          if (typeof left === "number" && left === 0) continue;
          return 1;
        }

        const comparison = compareQualifier(left, right);
        if (comparison !== 0) return comparison;
      }

      return 0;
    }

    function compareVersions(leftVersion, rightVersion) {
      const left = tokenizeVersion(leftVersion);
      const right = tokenizeVersion(rightVersion);

      if (!left || !right) return null;

      const coreComparison = compareCore(left.core, right.core);
      if (coreComparison !== 0) return coreComparison;

      return comparePrerelease(left.prerelease, right.prerelease);
    }

    function satisfiesLowerBound(version, lowerBound) {
      const parsedVersion = tokenizeVersion(version);
      const parsedLowerBound = tokenizeVersion(lowerBound);
      if (!parsedVersion || !parsedLowerBound) return false;

      // Retire-style repositories sometimes use a branch prefix such as "3" or
      // "13.0" as a lower bound for prerelease versions on that branch.
      if (
        parsedLowerBound.prerelease.length === 0 &&
        parsedLowerBound.coreSegmentCount < 3
      ) {
        for (let index = 0; index < parsedLowerBound.core.length; index += 1) {
          const actual = parsedVersion.core[index] ?? 0;
          const minimum = parsedLowerBound.core[index];

          if (actual > minimum) return true;
          if (actual < minimum) return false;
        }

        return true;
      }

      const comparison = compareVersions(version, lowerBound);
      return comparison !== null && comparison >= 0;
    }

    function versionsEqual(left, right) {
      const normalizedLeft = normalizeVersionString(left);
      const normalizedRight = normalizeVersionString(right);
      return normalizedLeft !== null && normalizedLeft === normalizedRight;
    }

    function isVersionInRange(version, range) {
      if (!range || typeof range !== "object") return false;

      if (
        (range.excludes || []).some((excluded) =>
          versionsEqual(version, excluded),
        )
      ) {
        return false;
      }

      if (range.atOrAbove && !satisfiesLowerBound(version, range.atOrAbove)) {
        return false;
      }

      if (range.below) {
        const upperComparison = compareVersions(version, range.below);
        if (upperComparison === null || upperComparison >= 0) return false;
      }

      return Boolean(range.atOrAbove || range.below);
    }

    function listVulnerabilityRanges(vulnerability) {
      if (!vulnerability || typeof vulnerability !== "object") return [];

      if (
        Array.isArray(vulnerability.ranges) &&
        vulnerability.ranges.length > 0
      ) {
        return vulnerability.ranges;
      }

      // Upstream retire.js records declare the bounds directly on the vulnerability.
      if (vulnerability.below || vulnerability.atOrAbove) {
        return [
          {
            below: vulnerability.below,
            atOrAbove: vulnerability.atOrAbove,
            excludes: vulnerability.excludes,
          },
        ];
      }

      return [];
    }

    function findMatchingRange(version, vulnerability) {
      return (
        listVulnerabilityRanges(vulnerability).find((range) =>
          isVersionInRange(version, range),
        ) || null
      );
    }

    function isVersionVulnerable(version, vulnerability) {
      return findMatchingRange(version, vulnerability) !== null;
    }

    function getVulnerabilitiesForVersion(metadata, version) {
      if (!metadata || !Array.isArray(metadata.vulnerabilities)) return [];

      const findings = [];

      for (const vulnerability of metadata.vulnerabilities) {
        const matchingRange = findMatchingRange(version, vulnerability);
        if (!matchingRange) continue;

        findings.push({
          severity: vulnerability.severity || "unknown",
          summary:
            vulnerability.summary ||
            vulnerability.identifiers?.summary ||
            "Unknown vulnerability",
          cve: vulnerability.identifiers?.CVE || [],
          cwe: vulnerability.cwe || [],
          info: vulnerability.info || [],
          below: matchingRange.below,
          atOrAbove: matchingRange.atOrAbove,
          excludes: matchingRange.excludes || [],
        });
      }

      return findings;
    }

    function validateRepository(repository) {
      const errors = [];

      if (
        !repository ||
        typeof repository !== "object" ||
        Array.isArray(repository)
      ) {
        return ["Repository must be an object"];
      }

      for (const [library, metadata] of Object.entries(repository)) {
        if (!metadata || typeof metadata !== "object") {
          errors.push(`${library}: metadata must be an object`);
          continue;
        }

        if (
          metadata.extractors !== undefined &&
          (!metadata.extractors ||
            typeof metadata.extractors !== "object" ||
            Array.isArray(metadata.extractors))
        ) {
          errors.push(`${library}: extractors must be an object`);
        }

        for (const [index, vulnerability] of (
          metadata.vulnerabilities || []
        ).entries()) {
          const ranges = listVulnerabilityRanges(vulnerability);

          if (ranges.length === 0) {
            errors.push(
              `${library}.vulnerabilities[${index}]: ranges must be a non-empty array`,
            );
            continue;
          }

          for (const [rangeIndex, range] of ranges.entries()) {
            const rangePath =
              ranges === vulnerability.ranges
                ? `${library}.vulnerabilities[${index}].ranges[${rangeIndex}]`
                : `${library}.vulnerabilities[${index}]`;

            if (
              !range ||
              typeof range !== "object" ||
              (!range.below && !range.atOrAbove)
            ) {
              errors.push(
                `${rangePath}: range must declare below or atOrAbove`,
              );
            }

            if (
              range.excludes !== undefined &&
              !Array.isArray(range.excludes)
            ) {
              errors.push(`${rangePath}: excludes must be an array`);
            }

            for (const boundaryName of ["below", "atOrAbove"]) {
              if (
                range[boundaryName] &&
                !tokenizeVersion(range[boundaryName])
              ) {
                errors.push(`${rangePath}.${boundaryName}: invalid version`);
              }
            }

            for (const [excludeIndex, excludedVersion] of (
              range.excludes || []
            ).entries()) {
              if (!tokenizeVersion(excludedVersion)) {
                errors.push(
                  `${rangePath}.excludes[${excludeIndex}]: invalid version`,
                );
              }
            }
          }
        }
      }

      return errors;
    }

    // Prefer a downloaded repository over the bundled one, but only when it is usable:
    // an empty or broken cache must never disable vulnerability detection silently.
    function selectRepository(bundled, cached) {
      if (!cached || typeof cached !== "object") return bundled;
      if (Object.keys(cached).length === 0) return bundled;
      if (validateRepository(cached).length > 0) return bundled;
      return cached;
    }

    function isRepositoryStale(fetchedAt, maxAgeMs, now) {
      if (!Number.isFinite(fetchedAt)) return true;
      return now - fetchedAt >= maxAgeMs;
    }

    return {
      compareVersions,
      findMatchingRange,
      getVulnerabilitiesForVersion,
      isRepositoryStale,
      isVersionInRange,
      isVersionVulnerable,
      listVulnerabilityRanges,
      normalizeVersionString,
      satisfiesLowerBound,
      selectRepository,
      tokenizeVersion,
      validateRepository,
    };
  },
);
