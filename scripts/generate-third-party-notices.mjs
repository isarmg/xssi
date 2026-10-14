import {
  closeSync,
  constants,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  openSync,
  readFileSync,
  readdirSync,
  realpathSync,
  renameSync,
  rmSync,
  symlinkSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { createHash } from "node:crypto";
import { tmpdir } from "node:os";
import {
  basename,
  dirname,
  isAbsolute,
  join,
  relative,
  resolve,
} from "node:path";

const LICENSE_FILE_PATTERN =
  /^(?:licen[cs]e|copying|notice|unlicense)(?:[._-].*)?$/iu;
const ALLOWED_SPDX_LICENSES = new Set([
  "0BSD",
  "Apache-2.0",
  "BSD-2-Clause",
  "BSD-3-Clause",
  "BSL-1.0",
  "ISC",
  "LGPL-2.1-or-later",
  "MIT",
  "MIT-0",
  "OpenSSL",
  "Unicode-3.0",
  "Unlicense",
  "Zlib",
]);
const ALLOWED_SPDX_EXCEPTIONS = new Set([
  "LLVM-exception",
]);
const CURATED_LEGACY_LICENSE_EXPRESSIONS = new Map([
  ["MIT/Apache-2.0", "MIT OR Apache-2.0"],
  ["Unlicense/MIT", "Unlicense OR MIT"],
]);
const PERMISSIVE_SPDX_LICENSES = new Set(
  [...ALLOWED_SPDX_LICENSES].filter(identifier =>
    identifier !== "LGPL-2.1-or-later"
  ),
);
const UTF8_DECODER = new TextDecoder("utf-8", { fatal: true });

const arguments_ = process.argv.slice(2);
if (arguments_.length === 1 && arguments_[0] === "--self-test") {
  runSelfTest();
  process.exit(0);
}
if (arguments_.length !== 5) {
  throw new Error(
    "Usage: generate-third-party-notices.mjs " +
      "<cargo-metadata.json> <vendor-root> <license-root> <output> <root-package>",
  );
}

const [metadataPath, vendorRoot, licenseRoot, outputPath, rootName] = arguments_;
const metadata = JSON.parse(readFileSync(metadataPath, "utf8"));
const output = generateNotices(metadata, vendorRoot, licenseRoot, rootName);
writeAtomically(outputPath, output);

function generateNotices(metadataDocument, vendorPath, licensePath, rootName = "xczs") {
  assertMetadata(metadataDocument);
  const physicalVendorRoot = realpathSync(resolve(vendorPath));
  // Keep validating the caller-supplied project root for a stable CLI, but do
  // not use its generic license files as substitutes for an upstream notice.
  // MIT-family licenses carry package-specific copyright notices, so a
  // project-wide fallback would silently misattribute another package.
  realpathSync(resolve(licensePath));
  const packagesById = new Map(
    metadataDocument.packages.map(package_ => [package_.id, package_]),
  );
  const nodesById = new Map(
    metadataDocument.resolve.nodes.map(node => [node.id, node]),
  );
  const workspaceRoots = metadataDocument.packages.filter(
    package_ => package_.source === null && package_.name === rootName,
  );
  if (
    workspaceRoots.length !== 1 ||
    workspaceRoots[0].name !== rootName
  ) {
    throw new Error("expected exactly one selected local workspace package");
  }

  const reachable = collectReleaseDependencies(
    workspaceRoots[0].id,
    nodesById,
    new Set(metadataDocument.packages.filter(package_ =>
      package_.targets?.some(target => target.kind.includes("proc-macro"))).map(package_ => package_.id)),
  );
  const packages = [...reachable]
    .map(id => packagesById.get(id))
    .filter(package_ => package_?.source !== null)
    .sort(comparePackages);
  if (packages.length === 0) {
    throw new Error("Cargo metadata contains no third-party release dependency");
  }

  const textsByDigest = new Map();
  const packageRecords = packages.map(package_ => {
    validateLicenseExpression(package_);
    const sourceDirectory = realpathSync(dirname(package_.manifest_path));
    assertContained(physicalVendorRoot, sourceDirectory, package_.name);
    const licenseFiles = findLicenseFiles(
      package_,
      sourceDirectory,
      physicalVendorRoot,
    );
    const digests = licenseFiles.map(path => {
      const bytes = readFileSync(path);
      if (bytes.includes(0)) {
        throw new Error(
          `license text contains a NUL byte for ${package_.name}`,
        );
      }
      let text;
      try {
        text = UTF8_DECODER.decode(bytes);
      } catch {
        throw new Error(
          `license text is not valid UTF-8 for ${package_.name}`,
        );
      }
      const normalized = text
        .replaceAll("\r\n", "\n")
        .replaceAll("\r", "\n")
        .trimEnd() + "\n";
      if (normalized.trim().length === 0) {
        throw new Error(`license text is empty for ${package_.name}`);
      }
      const digest = createHash("sha256").update(normalized).digest("hex");
      const record = textsByDigest.get(digest) || {
        digest,
        names: new Set(),
        packages: new Set(),
        text: normalized,
      };
      record.names.add(basename(path));
      record.packages.add(`${package_.name} ${package_.version}`);
      textsByDigest.set(digest, record);
      return digest;
    });
    return {
      digests: [...new Set(digests)].sort(),
      license: package_.license || "SEE LICENSE FILE",
      name: package_.name,
      version: package_.version,
    };
  });

  const lines = [
    "THIRD-PARTY LICENSES AND NOTICES",
    "",
    "This file is generated from Cargo's locked, non-development dependency " +
      "graph. Each package entry names the declared SPDX expression and the " +
      "SHA-256 digest of the included license text.",
    "",
    "PACKAGE INDEX",
    "",
  ];
  for (const record of packageRecords) {
    lines.push(
      `${record.name} ${record.version}`,
      `  Declared license: ${record.license}`,
      ...record.digests.map(digest => `  License text SHA-256: ${digest}`),
      "",
    );
  }
  lines.push("LICENSE TEXTS", "");
  for (const record of [...textsByDigest.values()].sort(
    (left, right) => left.digest.localeCompare(right.digest),
  )) {
    lines.push(
      `SHA-256: ${record.digest}`,
      `Source names: ${[...record.names].sort().join(", ")}`,
      `Used by: ${[...record.packages].sort().join(", ")}`,
      "",
      record.text.trimEnd(),
      "",
      "=".repeat(78),
      "",
    );
  }
  return `${lines.join("\n").trimEnd()}\n`;
}

function assertMetadata(metadata) {
  if (
    !metadata ||
    !Array.isArray(metadata.packages) ||
    !metadata.resolve ||
    !Array.isArray(metadata.resolve.nodes)
  ) {
    throw new Error("invalid Cargo metadata document");
  }
}

function collectReleaseDependencies(rootId, nodesById, compileTime = new Set()) {
  const reachable = new Set([rootId]);
  const pending = [rootId];
  while (pending.length > 0) {
    const id = pending.pop();
    const node = nodesById.get(id);
    if (!node) throw new Error(`Cargo metadata is missing resolve node ${id}`);
    for (const dependency of node.deps) {
      const included = dependency.dep_kinds.length === 0 ||
        dependency.dep_kinds.some(kind => kind.kind === null);
      if (included && !compileTime.has(dependency.pkg) && !reachable.has(dependency.pkg)) {
        reachable.add(dependency.pkg);
        pending.push(dependency.pkg);
      }
    }
  }
  return reachable;
}

function comparePackages(left, right) {
  return left.name.localeCompare(right.name) ||
    left.version.localeCompare(right.version) ||
    left.id.localeCompare(right.id);
}

function validateLicenseExpression(package_) {
  const expression = package_.license;
  if (!expression) {
    throw new Error(
      `dependency has no declared SPDX license expression: ` +
        `${package_.name} ${package_.version}`,
    );
  }
  let parsed;
  try {
    parsed = parseSpdxExpression(
      CURATED_LEGACY_LICENSE_EXPRESSIONS.get(expression) || expression,
    );
    validateSpdxIdentifiers(parsed);
  } catch (error) {
    throw new Error(
      `dependency has an invalid or unapproved SPDX expression: ` +
        `${package_.name} ${package_.version}: ${error.message}`,
      { cause: error },
    );
  }
  if (!hasPermissiveLicenseChoice(parsed)) {
    throw new Error(
      `dependency has no fully permissive SPDX license choice: ` +
        `${package_.name} ${package_.version}`,
    );
  }
}

function parseSpdxExpression(expression) {
  const tokens = [];
  let offset = 0;
  while (offset < expression.length) {
    const whitespace = /^[\t\n\r ]+/u.exec(expression.slice(offset));
    if (whitespace) {
      offset += whitespace[0].length;
      continue;
    }
    const character = expression[offset];
    if (character === "(" || character === ")") {
      tokens.push(character);
      offset++;
      continue;
    }
    const identifier =
      /^[0-9A-Za-z][0-9A-Za-z.+-]*/u.exec(expression.slice(offset));
    if (!identifier) {
      throw new Error(`unexpected token at byte ${offset}`);
    }
    tokens.push(identifier[0]);
    offset += identifier[0].length;
  }
  if (tokens.length === 0) throw new Error("empty expression");

  let index = 0;
  const peek = () => tokens[index];
  const take = expected => {
    const token = tokens[index];
    if (token !== expected) {
      throw new Error(`expected ${expected}, found ${token || "end"}`);
    }
    index++;
    return token;
  };
  const parsePrimary = () => {
    if (peek() === "(") {
      take("(");
      const node = parseOr();
      take(")");
      return node;
    }
    const identifier = peek();
    if (
      !identifier ||
      [")", "AND", "OR", "WITH"].includes(identifier)
    ) {
      throw new Error(`expected SPDX identifier, found ${identifier || "end"}`);
    }
    index++;
    return { type: "license", identifier, exception: null };
  };
  const parseWith = () => {
    const node = parsePrimary();
    if (peek() !== "WITH") return node;
    take("WITH");
    if (node.type !== "license") {
      throw new Error("WITH must follow one license identifier");
    }
    const exception = peek();
    if (
      !exception ||
      [")", "AND", "OR", "WITH"].includes(exception)
    ) {
      throw new Error(`expected SPDX exception, found ${exception || "end"}`);
    }
    index++;
    return { ...node, exception };
  };
  const parseAnd = () => {
    let node = parseWith();
    while (peek() === "AND") {
      take("AND");
      node = { type: "and", left: node, right: parseWith() };
    }
    return node;
  };
  const parseOr = () => {
    let node = parseAnd();
    while (peek() === "OR") {
      take("OR");
      node = { type: "or", left: node, right: parseAnd() };
    }
    return node;
  };

  const parsed = parseOr();
  if (index !== tokens.length) {
    throw new Error(`unexpected token ${tokens[index]}`);
  }
  return parsed;
}

function validateSpdxIdentifiers(node) {
  if (node.type === "license") {
    if (!ALLOWED_SPDX_LICENSES.has(node.identifier)) {
      throw new Error(`unapproved license identifier ${node.identifier}`);
    }
    if (node.exception !== null) {
      if (!ALLOWED_SPDX_EXCEPTIONS.has(node.exception)) {
        throw new Error(`unapproved license exception ${node.exception}`);
      }
      if (
        node.exception === "LLVM-exception" &&
        node.identifier !== "Apache-2.0"
      ) {
        throw new Error(
          `LLVM-exception is not approved with ${node.identifier}`,
        );
      }
    }
    return;
  }
  validateSpdxIdentifiers(node.left);
  validateSpdxIdentifiers(node.right);
}

function hasPermissiveLicenseChoice(node) {
  if (node.type === "license") {
    return PERMISSIVE_SPDX_LICENSES.has(node.identifier);
  }
  if (node.type === "or") {
    return (
      hasPermissiveLicenseChoice(node.left) ||
      hasPermissiveLicenseChoice(node.right)
    );
  }
  return (
    hasPermissiveLicenseChoice(node.left) &&
    hasPermissiveLicenseChoice(node.right)
  );
}

function findLicenseFiles(
  package_,
  sourceDirectory,
  physicalVendorRoot,
) {
  const candidates = [];
  if (package_.license_file) {
    candidates.push(resolve(sourceDirectory, package_.license_file));
  }
  candidates.push(
    ...readdirSync(sourceDirectory, { withFileTypes: true })
      .filter(entry => LICENSE_FILE_PATTERN.test(entry.name))
      .map(entry => join(sourceDirectory, entry.name)),
  );
  if (candidates.length === 0) {
    throw new Error(
      `dependency has no distributable license text: ` +
        `${package_.name} ${package_.version}`,
    );
  }

  return [...new Set(candidates)].map(candidate => {
    const metadata = lstatSync(candidate);
    if (!metadata.isFile() || metadata.isSymbolicLink()) {
      throw new Error(
        `dependency license is not a regular no-follow file: ${candidate}`,
      );
    }
    const physical = realpathSync(candidate);
    if (!isContained(sourceDirectory, physical)) {
      throw new Error(
        `dependency license escapes its own package: ${candidate}`,
      );
    }
    assertContained(physicalVendorRoot, physical, package_.name);
    return physical;
  });
}

function assertContained(root, candidate, packageName) {
  if (!isContained(root, candidate)) {
    throw new Error(
      `dependency source escapes the vendor root: ${packageName}`,
    );
  }
}

function isContained(root, candidate) {
  const relativePath = relative(root, candidate);
  return (
    relativePath === "" ||
    (!relativePath.startsWith(`..${process.platform === "win32" ? "\\" : "/"}`) &&
      relativePath !== ".." &&
      !isAbsolute(relativePath))
  );
}

function writeAtomically(path, value) {
  const resolved = resolve(path);
  const temporary = join(
    dirname(resolved),
    `.xssi-third-party-${process.pid}.tmp`,
  );
  let descriptor;
  try {
    descriptor = openSync(
      temporary,
      constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY,
      0o600,
    );
    writeFileSync(descriptor, value, "utf8");
    closeSync(descriptor);
    descriptor = undefined;
    renameSync(temporary, resolved);
  } finally {
    if (descriptor !== undefined) closeSync(descriptor);
    try {
      unlinkSync(temporary);
    } catch (error) {
      if (error?.code !== "ENOENT") {
        // Cleanup failure must replace success instead of being hidden.
        // eslint-disable-next-line no-unsafe-finally
        throw error;
      }
    }
  }
}

function runSelfTest() {
  const root = mkdtempSync(join(tmpdir(), "xczs-third-party-test-"));
  try {
    const vendor = join(root, "vendor");
    const licenses = join(root, "licenses");
    const packageDirectory = join(vendor, "dependency-1.0.0");
    const devDirectory = join(vendor, "dev-only-1.0.0");
    const siblingDirectory = join(vendor, "sibling-1.0.0");
    mkdirSync(packageDirectory, { recursive: true });
    mkdirSync(devDirectory, { recursive: true });
    mkdirSync(siblingDirectory, { recursive: true });
    mkdirSync(licenses);
    writeFileSync(join(packageDirectory, "Cargo.toml"), "[package]\n");
    writeFileSync(join(packageDirectory, "LICENSE"), "Dependency license\n");
    writeFileSync(join(devDirectory, "Cargo.toml"), "[package]\n");
    writeFileSync(join(devDirectory, "LICENSE"), "Dev-only license\n");
    writeFileSync(join(siblingDirectory, "LICENSE"), "Sibling license\n");
    writeFileSync(join(licenses, "LICENSE-MIT"), "Canonical MIT text\n");
    writeFileSync(
      join(licenses, "LICENSE-APACHE"),
      "Canonical Apache text\n",
    );
    const localId = "path+file:///source#xczs@1.0.0";
    const dependencyId =
      "registry+https://example.invalid#index/dependency@1.0.0";
    const devId = "registry+https://example.invalid#index/dev-only@1.0.0";
    const metadata = {
      packages: [
        {
          id: localId,
          license: "MIT OR Apache-2.0",
          license_file: null,
          manifest_path: join(root, "Cargo.toml"),
          name: "xczs",
          source: null,
          version: "1.0.0",
        },
        {
          id: dependencyId,
          license: "MIT",
          license_file: null,
          manifest_path: join(packageDirectory, "Cargo.toml"),
          name: "dependency",
          source: "registry+https://example.invalid/index",
          version: "1.0.0",
        },
        {
          id: devId,
          license: "MIT",
          license_file: null,
          manifest_path: join(devDirectory, "Cargo.toml"),
          name: "dev-only",
          source: "registry+https://example.invalid/index",
          version: "1.0.0",
        },
      ],
      resolve: {
        nodes: [
          {
            id: localId,
            deps: [
              {
                dep_kinds: [{ kind: null, target: null }],
                name: "dependency",
                pkg: dependencyId,
              },
              {
                dep_kinds: [{ kind: "dev", target: null }],
                name: "dev_only",
                pkg: devId,
              },
            ],
          },
          { id: dependencyId, deps: [] },
          { id: devId, deps: [] },
        ],
      },
    };
    const notice = generateNotices(metadata, vendor, licenses);
    if (
      !notice.includes("dependency 1.0.0") ||
      notice.includes("dev-only") ||
      !notice.includes("Dependency license")
    ) {
      throw new Error("notice self-test produced the wrong dependency set");
    }

    const noAttribution = structuredClone(metadata);
    noAttribution.packages[1].license = "MIT-0";
    const noAttributionNotice = generateNotices(noAttribution, vendor, licenses);
    if (!noAttributionNotice.includes("MIT-0") ||
        !noAttributionNotice.includes("Dependency license")) {
      throw new Error("notice self-test did not preserve the MIT-0 upstream text");
    }

    const unknown = structuredClone(metadata);
    unknown.packages[1].license = "LicenseRef-Proprietary";
    let rejectedUnknown = false;
    try {
      generateNotices(unknown, vendor, licenses);
    } catch {
      rejectedUnknown = true;
    }
    if (!rejectedUnknown) {
      throw new Error("notice self-test accepted an unknown license");
    }

    const mandatoryCopyleft = structuredClone(metadata);
    mandatoryCopyleft.packages[1].license =
      "LGPL-2.1-or-later AND (MIT OR Apache-2.0)";
    let rejectedMandatoryCopyleft = false;
    try {
      generateNotices(mandatoryCopyleft, vendor, licenses);
    } catch {
      rejectedMandatoryCopyleft = true;
    }
    if (!rejectedMandatoryCopyleft) {
      throw new Error("notice self-test accepted mandatory copyleft");
    }

    const optionalCopyleft = structuredClone(metadata);
    optionalCopyleft.packages[1].license =
      "(LGPL-2.1-or-later AND Apache-2.0) OR MIT";
    generateNotices(optionalCopyleft, vendor, licenses);

    const invalidExpression = structuredClone(metadata);
    invalidExpression.packages[1].license = "MIT Apache-2.0";
    let rejectedInvalidExpression = false;
    try {
      generateNotices(invalidExpression, vendor, licenses);
    } catch {
      rejectedInvalidExpression = true;
    }
    if (!rejectedInvalidExpression) {
      throw new Error("notice self-test accepted invalid SPDX syntax");
    }

    const licenseFileOnly = structuredClone(metadata);
    licenseFileOnly.packages[1].license = null;
    licenseFileOnly.packages[1].license_file = "LICENSE";
    let rejectedLicenseFileOnly = false;
    try {
      generateNotices(licenseFileOnly, vendor, licenses);
    } catch {
      rejectedLicenseFileOnly = true;
    }
    if (!rejectedLicenseFileOnly) {
      throw new Error(
        "notice self-test accepted an unreviewed license-file-only package",
      );
    }

    const siblingEscape = structuredClone(metadata);
    siblingEscape.packages[1].license_file = "../sibling-1.0.0/LICENSE";
    let rejectedSiblingEscape = false;
    try {
      generateNotices(siblingEscape, vendor, licenses);
    } catch {
      rejectedSiblingEscape = true;
    }
    if (!rejectedSiblingEscape) {
      throw new Error("notice self-test accepted a sibling license path");
    }

    unlinkSync(join(packageDirectory, "LICENSE"));
    symlinkSync("/etc/passwd", join(packageDirectory, "LICENSE"));
    let rejectedLink = false;
    try {
      generateNotices(metadata, vendor, licenses);
    } catch {
      rejectedLink = true;
    }
    if (!rejectedLink) {
      throw new Error("notice self-test followed a license symlink");
    }
    unlinkSync(join(packageDirectory, "LICENSE"));
    let rejectedMissingText = false;
    try {
      generateNotices(metadata, vendor, licenses);
    } catch {
      rejectedMissingText = true;
    }
    if (!rejectedMissingText) {
      throw new Error("notice self-test substituted a generic license text");
    }
  } finally {
    rmSync(root, { force: true, recursive: true });
  }
  process.stdout.write("third-party notice self-test passed\n");
}
