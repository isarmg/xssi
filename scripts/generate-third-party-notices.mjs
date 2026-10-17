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
  "CC0-1.0",
  "CDLA-Permissive-2.0",
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
  ["Apache-2.0/MIT", "Apache-2.0 OR MIT"],
  ["Apache-2.0 / MIT", "Apache-2.0 OR MIT"],
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
if (arguments_.length !== 6) {
  throw new Error(
    "Usage: generate-third-party-notices.mjs " +
      "<cargo-metadata.json> <vendor-root> <license-root> <output> <root-package> <actual-runtime-sbom.json>",
  );
}

const [metadataPath, vendorRoot, licenseRoot, outputPath, rootName, bomPath] = arguments_;
const metadata = JSON.parse(readFileSync(metadataPath, "utf8"));
const output = generateNotices(metadata, vendorRoot, licenseRoot, rootName,
  JSON.parse(readFileSync(bomPath, "utf8")));
writeAtomically(outputPath, output);

function generateNotices(metadataDocument, vendorPath, licensePath, rootName, bom) {
  assertMetadata(metadataDocument);
  const physicalVendorRoot = realpathSync(resolve(vendorPath));
  // The project root carries controlled source receipts. Its generic license
  // files cannot substitute for an upstream notice.
  // MIT-family licenses carry package-specific copyright notices, so a
  // project-wide fallback would silently misattribute another package.
  const physicalLicenseRoot = realpathSync(resolve(licensePath));
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
  const actual = actualComponents(bom, packages, rootName, workspaceRoots[0].version);
  const provenance = JSON.parse(readFileSync(physicalRegular(physicalLicenseRoot,
    join(physicalLicenseRoot, "xssi-cargo-source-checksums.json")), "utf8"));
  if (provenance.format_version !== 1 || !Array.isArray(provenance.packages) || provenance.packages.length > 4096) {
    throw new Error("unsupported locked Cargo source checksum receipt");
  }
  const sourceById = new Map(provenance.packages.map(item => [item.id,item]));
  if (sourceById.size !== provenance.packages.length) throw new Error("duplicate locked Cargo source identity");

  const textsByDigest = new Map();
  const packageRecords = packages.map(package_ => {
    const expression = validateLicenseExpression(package_, actual.get(package_.id));
    const sourceDirectory = realpathSync(dirname(package_.manifest_path));
    assertContained(physicalVendorRoot, sourceDirectory, package_.name);
    const checksum = JSON.parse(readFileSync(physicalRegular(sourceDirectory,
      join(sourceDirectory, ".cargo-checksum.json")), "utf8"));
    const sourceRecord = sourceById.get(package_.id);
    if (!sourceRecord || sourceRecord.name !== package_.name ||
        sourceRecord.version !== package_.version || sourceRecord.source !== package_.source ||
        checksum.package !== sourceRecord.checksum ||
        (package_.source.startsWith("registry+") && !/^[0-9a-f]{64}$/u.test(sourceRecord.checksum))) {
      throw new Error("upstream vendor source differs from the selected immutable Cargo lock");
    }
    const licenseFiles = findLicenseFiles(
      package_,
      sourceDirectory,
      physicalVendorRoot,
      physicalLicenseRoot,
    );
    const sources = [];
    const includedChoices = new Set(licenseFiles.map(item => item.selected).filter(Boolean));
    if (includedChoices.size > 1) throw new Error("conflicting original license choices");
    const digests = licenseFiles.map(({path, source, kind}) => {
      if (source) sources.push(`${kind === "standard-spdx" ? "Standard SPDX license text source" : kind === "publisher-declaration" ? "Publisher license declaration source" : "Original license source"}: ${source}`);
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
      expression,
      sources: [...new Set(sources)].sort(),
      selected: [...includedChoices][0],
      name: package_.name,
      version: package_.version,
    };
  });

  const lines = [
    "THIRD-PARTY LICENSES AND NOTICES",
    "",
    "This file is generated from Cargo's locked, non-development dependency " +
      "graph. Each package entry preserves the declared license metadata and the " +
      "SHA-256 digest of the included license text.",
    "Publisher declarations and standard SPDX texts are labeled separately; " +
      "standard templates do not identify a publisher's copyright holders.",
    "",
    "PACKAGE INDEX",
    "",
  ];
  for (const record of packageRecords) {
    lines.push(
      `${record.name} ${record.version}`,
      `  Declared license: ${record.license}`,
      ...(record.expression !== record.license ?
        [`  Resolved SPDX expression: ${record.expression}`] : []),
      ...record.sources.map(source => `  ${source}`),
      ...(record.selected ? [`  Included license choice: ${record.selected}`] : []),
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

function actualComponents(bom, packages, rootName, rootVersion) {
  if (bom?.bomFormat !== "CycloneDX" || bom.specVersion !== "1.5" || bom.version !== 1 ||
      bom.metadata?.component?.name !== rootName || bom.metadata.component.version !== rootVersion || !Array.isArray(bom.components)) {
    throw new Error("notice input is not the selected actual runtime SBOM");
  }
  const components = new Map();
  const visit = items => {
    for (const item of items) {
      if (!item || typeof item["bom-ref"] !== "string" || components.has(item["bom-ref"])) {
        throw new Error("duplicate or missing actual component identity");
      }
      components.set(item["bom-ref"], item);
      visit(item.components || []);
    }
  };
  visit([bom.metadata.component, ...bom.components]);
  const result = new Map();
  for (const package_ of packages) {
    const item = components.get(package_.id);
    if (!item || item.name !== package_.name || item.version !== package_.version ||
        !Array.isArray(item.licenses) || item.licenses.length !== 1 ||
        typeof item.licenses[0]?.expression !== "string") {
      throw new Error("notice license is not bound to its actual selected Cargo component");
    }
    result.set(package_.id, item.licenses[0].expression);
  }
  return result;
}

function validateLicenseExpression(package_, actualExpression) {
  const expression = package_.license;
  if (!expression) {
    throw new Error(
      `dependency has no declared SPDX license expression: ` +
        `${package_.name} ${package_.version}`,
    );
  }
  let parsed;
  const normalized = CURATED_LEGACY_LICENSE_EXPRESSIONS.get(expression) || expression;
  try {
    parsed = parseSpdxExpression(normalized);
    validateSpdxIdentifiers(parsed);
    const actual = parseSpdxExpression(actualExpression);
    validateSpdxIdentifiers(actual);
    if (JSON.stringify(parsed) !== JSON.stringify(actual)) {
      throw new Error("mature SPDX expression differs from the original declaration");
    }
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
  return actualExpression;
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
  physicalLicenseRoot,
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
  const licenseDirectory = join(sourceDirectory, "LICENSES");
  if (existsPhysical(licenseDirectory)) {
    const info = lstatSync(licenseDirectory);
    if (!info.isDirectory() || info.isSymbolicLink() ||
        realpathSync(licenseDirectory) !== licenseDirectory) {
      throw new Error("upstream LICENSES is not a physical directory");
    }
    const entries = readdirSync(licenseDirectory, {withFileTypes: true});
    if (entries.length === 0 || entries.length > 32) {
      throw new Error("upstream LICENSES has an invalid entry count");
    }
    for (const entry of entries) {
      if (!entry.isFile() || entry.isSymbolicLink() || !entry.name.endsWith(".txt") ||
          !ALLOWED_SPDX_LICENSES.has(entry.name.slice(0, -4))) {
        throw new Error("upstream LICENSES has an unreviewed structure or filename");
      }
      candidates.push(join(licenseDirectory, entry.name));
    }
  }
  if (candidates.length === 0) {
    const upstream = recordedUpstreamLicenses(package_, sourceDirectory, physicalLicenseRoot);
    if (upstream) return upstream;
    throw new Error(
      `dependency has no distributable license text: ` +
        `${package_.name} ${package_.version}`,
    );
  }

  return [...new Set(candidates)].map(candidate => {
    const physical = physicalRegular(sourceDirectory, candidate);
    assertContained(physicalVendorRoot, physical, package_.name);
    const checksum = JSON.parse(readFileSync(physicalRegular(sourceDirectory,
      join(sourceDirectory, ".cargo-checksum.json")), "utf8"));
    const relativePath = relative(sourceDirectory, physical).split("\\").join("/");
    if (checksum.files?.[relativePath] !== createHash("sha256").update(readFileSync(physical)).digest("hex")) {
      throw new Error("original license differs from Cargo's immutable vendored source");
    }
    return {path: physical, source: null};
  });
}

function existsPhysical(path) {
  try {lstatSync(path); return true;}
  catch (error) {if (error.code === "ENOENT") return false; throw error;}
}

function physicalRegular(root, path) {
  path = resolve(path);
  assertContained(root, path, "original license");
  let current = root;
  for (const segment of relative(root, path).split(/[\\/]/u)) {
    current = join(current, segment);
    const info = lstatSync(current);
    if (info.isSymbolicLink() || (current !== path && !info.isDirectory())) {
      throw new Error("original license path contains an alias or non-directory parent");
    }
  }
  const info = lstatSync(path);
  if (!info.isFile() || info.nlink !== 1 || info.size <= 0 || info.size > 1024 * 1024) {
    throw new Error("original license is not a bounded single-link regular file");
  }
  return path;
}

function recordedUpstreamLicenses(package_, sourceDirectory, physicalLicenseRoot) {
  const root = join(physicalLicenseRoot, "xssi-upstream-licenses");
  if (!existsPhysical(root)) return null;
  if (!lstatSync(root).isDirectory() || lstatSync(root).isSymbolicLink() || realpathSync(root) !== root) {
    throw new Error("upstream license receipt root is not physical");
  }
  const receipt = JSON.parse(readFileSync(physicalRegular(root, join(root, "receipt.json")), "utf8"));
  if (receipt.format_version !== 1 || !Array.isArray(receipt.packages) || receipt.packages.length > 4096) {
    throw new Error("unsupported upstream license receipt");
  }
  const matches = receipt.packages.filter(item => item.name === package_.name &&
    item.version === package_.version && item.source === package_.source);
  if (matches.length === 0) return null;
  if (matches.length !== 1) throw new Error("duplicate upstream license package identity");
  const record = matches[0];
  if (!/^[0-9a-f]{40}$/u.test(record.revision) ||
      !/^https:\/\/github\.com\/[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+(?:\.git)?$/u.test(record.repository)) {
    throw new Error("upstream original license lacks immutable repository provenance");
  }
  const checksum = JSON.parse(readFileSync(physicalRegular(sourceDirectory,
    join(sourceDirectory, ".cargo-checksum.json")), "utf8"));
  if (package_.source.startsWith("registry+") &&
      (!/^[0-9a-f]{64}$/u.test(record.package_checksum) || checksum.package !== record.package_checksum)) {
    throw new Error("upstream license receipt differs from its immutable crate archive");
  }
  if (package_.source.startsWith("registry+")) {
    const vcs = JSON.parse(readFileSync(physicalRegular(sourceDirectory,
      join(sourceDirectory, ".cargo_vcs_info.json")), "utf8"));
    if (vcs.git?.sha1 !== record.revision) {
      throw new Error("original license source revision differs from its crate provenance");
    }
  } else if (package_.source.startsWith("git+")) {
    const source = new URL(package_.source.slice(4));
    if (source.username || source.password || source.hash !== "#" + record.revision ||
        source.searchParams.get("rev") !== record.revision ||
        (source.origin + source.pathname).replace(/\.git$/u, "") !== record.repository.replace(/\.git$/u, "")) {
      throw new Error("original license source differs from its exact Cargo Git dependency");
    }
  } else throw new Error("unreviewed original license package source");
  if (record.selected_license !== undefined) {
    const selected = parseSpdxExpression(record.selected_license);
    validateSpdxIdentifiers(selected);
    const declaration = parseSpdxExpression(package_.license);
    const contains = node => JSON.stringify(node) === JSON.stringify(selected) ||
      (node.type === "or" && (contains(node.left) || contains(node.right)));
    if (!hasPermissiveLicenseChoice(selected) || !contains(declaration)) {
      throw new Error("included license choice is not offered by the publisher");
    }
  }
  if (!Array.isArray(record.licenses) || record.licenses.length === 0 || record.licenses.length > 32) {
    throw new Error("upstream license receipt has no complete original texts");
  }
  if (record.standard_license !== undefined &&
      (!["MIT", "Apache-2.0"].includes(record.standard_license) ||
       record.selected_license !== record.standard_license || record.licenses.length !== 2 ||
       record.licenses.filter(item => item.kind === "publisher-declaration").length !== 1 ||
       record.licenses.filter(item => item.kind === "standard-spdx").length !== 1)) {
    throw new Error("standard license text lacks one explicit publisher declaration and choice");
  }
  return record.licenses.map(item => {
    if (typeof item.path !== "string" || item.path.includes("\\") || item.path.split("/").some(part => !part || part === "." || part === "..") ||
        !/^[0-9a-f]{64}$/u.test(item.sha256) || typeof item.source !== "string" || !item.source.startsWith("https://") ||
        /[\r\n\0]/u.test(item.source)) throw new Error("invalid original license source receipt");
    const path = physicalRegular(root, resolve(root, item.path));
    if (createHash("sha256").update(readFileSync(path)).digest("hex") !== item.sha256) {
      throw new Error("original upstream license text differs from its source receipt");
    }
    if (item.kind === "publisher-declaration") {
      const original = physicalRegular(sourceDirectory, join(sourceDirectory, "Cargo.toml.orig"));
      if (record.standard_license === undefined || checksum.files?.["Cargo.toml.orig"] !== item.sha256 ||
          !readFileSync(path).equals(readFileSync(original)) ||
          item.source !== `https://static.crates.io/crates/${package_.name}/${package_.name}-${package_.version}.crate#Cargo.toml.orig`) {
        throw new Error("publisher license declaration differs from its exact crate archive");
      }
    } else if (item.kind === "standard-spdx") {
      if (record.standard_license === undefined ||
          item.source !== `https://spdx.org/licenses/${record.standard_license}.txt`) {
        throw new Error("standard license text differs from its reviewed SPDX source");
      }
    } else if (item.kind !== undefined) {
      throw new Error("unreviewed license source kind");
    }
    return {path, source: item.source, selected: record.selected_license, kind: item.kind};
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
    writeFileSync(join(packageDirectory, ".cargo-checksum.json"), JSON.stringify({package:"a".repeat(64),
      files:{LICENSE:createHash("sha256").update("Dependency license\n").digest("hex")}}));
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
    const fixtureBom = meta => ({bomFormat:"CycloneDX", specVersion:"1.5",version:1,
      metadata:{component:{name:"xczs", version:"1.0.0", "bom-ref":localId}},
      components:meta.packages.filter(item => item.source !== null).map(item => ({
        name:item.name,version:item.version,"bom-ref":item.id,
        licenses:[{expression:CURATED_LEGACY_LICENSE_EXPRESSIONS.get(item.license) || item.license}]}))});
    const noticesFor = (meta, bom=fixtureBom(meta)) => {
      writeFileSync(join(licenses, "xssi-cargo-source-checksums.json"), JSON.stringify({
        format_version:1,packages:meta.packages.filter(item => item.source !== null).map(item => ({
          id:item.id,name:item.name,version:item.version,source:item.source,checksum:"a".repeat(64)}))}));
      return generateNotices(meta,vendor,licenses,"xczs",bom);
    };
    const notice = noticesFor(metadata);
    if (
      !notice.includes("dependency 1.0.0") ||
      notice.includes("dev-only") ||
      !notice.includes("Dependency license")
    ) {
      throw new Error("notice self-test produced the wrong dependency set");
    }

    const fnv = {name: "fnv", version: "1.0.7",
      source: "registry+https://github.com/rust-lang/crates.io-index",
      license: "Apache-2.0 / MIT"};
    if (validateLicenseExpression(fnv, "Apache-2.0 OR MIT") !== "Apache-2.0 OR MIT" ||
        fnv.license !== "Apache-2.0 / MIT") {
      throw new Error("reviewed fnv metadata was not preserved and interpreted");
    }
    for (const altered of [{license: "Apache-2.0 / MIT / BSD-3-Clause"},
      {license:"LicenseRef-Proprietary / MIT"}, {license:"Apache-2.0 / GPL-3.0-only"}]) {
      let refused = false;
      try {validateLicenseExpression({...fnv, ...altered}, "Apache-2.0 OR MIT");}
      catch {refused = true;}
      if (!refused) throw new Error("unreviewed slash license metadata was accepted");
    }
    let mismatch = false;
    try {validateLicenseExpression(fnv, "Apache-2.0 AND MIT");}
    catch {mismatch = true;}
    if (!mismatch) throw new Error("mature SPDX interpretation changed the publisher's license choice");
    const forged=fixtureBom(metadata);forged.components[0].version="9.0.0";
    let identity = false;
    try {noticesFor(metadata,forged);} catch {identity=true;}
    if (!identity) throw new Error("notice accepted a license from another actual component");

    const noAttribution = structuredClone(metadata);
    noAttribution.packages[1].license = "MIT-0";
    const noAttributionNotice = noticesFor(noAttribution);
    if (!noAttributionNotice.includes("MIT-0") ||
        !noAttributionNotice.includes("Dependency license")) {
      throw new Error("notice self-test did not preserve the MIT-0 upstream text");
    }

    const unknown = structuredClone(metadata);
    unknown.packages[1].license = "LicenseRef-Proprietary";
    let rejectedUnknown = false;
    try {
      noticesFor(unknown);
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
      noticesFor(mandatoryCopyleft);
    } catch {
      rejectedMandatoryCopyleft = true;
    }
    if (!rejectedMandatoryCopyleft) {
      throw new Error("notice self-test accepted mandatory copyleft");
    }

    const optionalCopyleft = structuredClone(metadata);
    optionalCopyleft.packages[1].license =
      "(LGPL-2.1-or-later AND Apache-2.0) OR MIT";
    noticesFor(optionalCopyleft);

    const invalidExpression = structuredClone(metadata);
    invalidExpression.packages[1].license = "MIT Apache-2.0";
    let rejectedInvalidExpression = false;
    try {
      noticesFor(invalidExpression);
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
      noticesFor(licenseFileOnly);
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
      noticesFor(siblingEscape);
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
      noticesFor(metadata);
    } catch {
      rejectedLink = true;
    }
    if (!rejectedLink) {
      throw new Error("notice self-test followed a license symlink");
    }
    unlinkSync(join(packageDirectory, "LICENSE"));
    let rejectedMissingText = false;
    try {
      noticesFor(metadata);
    } catch {
      rejectedMissingText = true;
    }
    if (!rejectedMissingText) {
      throw new Error("notice self-test substituted a generic license text");
    }
    const declaration = '[package]\nname="dependency"\nversion="1.0.0"\nlicense="MIT"\n';
    const declarationSha = createHash("sha256").update(declaration).digest("hex");
    writeFileSync(join(packageDirectory, "Cargo.toml.orig"), declaration);
    writeFileSync(join(packageDirectory, ".cargo_vcs_info.json"), JSON.stringify({git:{sha1:"b".repeat(40)}}));
    writeFileSync(join(packageDirectory, ".cargo-checksum.json"), JSON.stringify({package:"a".repeat(64),files:{"Cargo.toml.orig":declarationSha}}));
    const reviewed = join(licenses, "xssi-upstream-licenses");
    const materials = join(reviewed, "dependency-1.0.0");
    mkdirSync(materials, {recursive:true});
    writeFileSync(join(materials, "PUBLISHER-LICENSE-DECLARATION.toml"), declaration);
    const standard = "MIT standard text fixture; no publisher copyright is invented.\n";
    writeFileSync(join(materials, "SPDX-MIT.txt"), standard);
    const licenseReceipt = {format_version:1,packages:[{
      name:"dependency",version:"1.0.0",source:metadata.packages[1].source,
      repository:"https://github.com/example/dependency",revision:"b".repeat(40),
      package_checksum:"a".repeat(64),standard_license:"MIT",selected_license:"MIT",licenses:[
        {path:"dependency-1.0.0/PUBLISHER-LICENSE-DECLARATION.toml",sha256:declarationSha,
         kind:"publisher-declaration",source:"https://static.crates.io/crates/dependency/dependency-1.0.0.crate#Cargo.toml.orig"},
        {path:"dependency-1.0.0/SPDX-MIT.txt",sha256:createHash("sha256").update(standard).digest("hex"),
         kind:"standard-spdx",source:"https://spdx.org/licenses/MIT.txt"}]}]};
    writeFileSync(join(reviewed,"receipt.json"),JSON.stringify(licenseReceipt));
    const standardNotice=noticesFor(metadata);
    if (!standardNotice.includes("Standard SPDX license text source:") ||
        !standardNotice.includes("Publisher license declaration source:") ||
        standardNotice.includes("Original license source: https://spdx.org/")) {
      throw new Error("notice did not distinguish publisher declarations from standard license text");
    }
    writeFileSync(join(materials,"PUBLISHER-LICENSE-DECLARATION.toml"),declaration+"# altered\n");
    let rejectedDeclaration=false;
    try {noticesFor(metadata);} catch {rejectedDeclaration=true;}
    if (!rejectedDeclaration) throw new Error("notice accepted a changed publisher declaration");
  } finally {
    rmSync(root, { force: true, recursive: true });
  }
  process.stdout.write("third-party notice self-test passed\n");
}
