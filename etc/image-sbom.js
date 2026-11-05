#!/usr/bin/env node
/*
 * image-sbom.js -- the SBOM (CycloneDX 1.6) of a vesvault/ves image.
 *
 *   node etc/image-sbom.js [--digest sha256:HEX] [--revision COMMIT] IMAGE > ves-<version>-image.cdx.json
 *   DOCKER="sudo docker" node etc/image-sbom.js vesvault/ves:1.37 > ves-1.37-image.cdx.json
 *
 * Run it from a libVES.c checkout that has the image's revision: its
 * org.opencontainers.image.revision label, or --revision for an image built
 * without labels. The liboqs build options are read from the Dockerfile at
 * that commit. Everything else is read from the image itself, pulled first:
 *
 *   - libVES.c and the ves CLI: version from `ves --version`, the commit from
 *     the revision label, SHA-256 of /usr/lib/libVES.so.1.0.0 and /usr/bin/ves
 *   - liboqs: built from source into /usr/local, so no package database and
 *     no image scanner sees it. Version from the library's file name, commit
 *     from the upstream tag, the KEMs it enables from `ves -Gl`
 *   - every Debian package dpkg lists as installed, as pkg:deb purls with the
 *     Debian release from os-release, so image scanners match them
 *
 * A published image is named by its manifest digest, which Docker Hub and GHCR
 * share for this repo's single-platform images: --digest, or the repository
 * digest a pull recorded. An image that was built and never pushed (CI's
 * build job) has no digest yet, so it is named by its image ID and marked
 * unpublished. Deterministic: no timestamp, and the serial number is derived
 * from the content, so the same image and revision give the same SBOM.
 *
 * It stops, writing nothing, if what it reads does not hold together: ves
 * and the version label disagree, the Dockerfile pins another liboqs, ML-KEM
 * is not among the KEMs, or libVES's own Debian dependencies are missing.
 */
'use strict';
const { execFileSync } = require('child_process');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');

const usage = () => {
    process.stderr.write('usage: node etc/image-sbom.js [--digest sha256:HEX] [--revision COMMIT] IMAGE\n');
    process.exit(64);
};
let image, optDigest, optRevision;
for (const argv = process.argv.slice(2); argv.length;) {
    const a = argv.shift();
    if (a === '--digest' && argv.length) optDigest = argv.shift();
    else if (a === '--revision' && argv.length) optRevision = argv.shift();
    else if (!a.startsWith('-') && !image) image = a;
    else usage();
}
if (!image) usage();
if (optDigest && !/^sha256:[0-9a-f]{64}$/.test(optDigest)) usage();
if (optRevision && !/^[0-9a-f]{40}$/.test(optRevision)) usage();
const docker = (process.env.DOCKER || 'docker').split(' ').filter(Boolean);
const run = (cmd, args, opts) => execFileSync(cmd, args, Object.assign({ encoding: 'utf8', maxBuffer: 64 << 20 }, opts));
const dk = (args, opts) => run(docker[0], docker.slice(1).concat(args), opts);
const sha256 = (file) => crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
const die = (msg) => { process.stderr.write(`image-sbom: ${msg}\n`); process.exit(1); };

// ---- the image
const info = JSON.parse(dk(['image', 'inspect', image]))[0];
const labels = (info.Config && info.Config.Labels) || {};
const labelRevision = labels['org.opencontainers.image.revision'];
if (labelRevision && optRevision && labelRevision !== optRevision) die(`${image} is labelled revision ${labelRevision}, not ${optRevision}`);
const revision = labelRevision || optRevision;
if (!revision) die(`${image} has no revision label; give --revision`);
let version = labels['org.opencontainers.image.version'];
const repoDigest = (info.RepoDigests || []).find((d) => /(^|\/)vesvault\/ves@sha256:/.test(d))
    || (info.RepoDigests || [])[0];
const pulledDigest = repoDigest ? repoDigest.split('@')[1] : null;
if (optDigest && pulledDigest && optDigest !== pulledDigest) die(`${image} was pulled as ${pulledDigest}, not ${optDigest}`);
const digest = optDigest || pulledDigest;   // null: never pushed

// Each path comes out of the container as a tar stream, unpacked by this
// process: with DOCKER="sudo docker" a plain `docker cp` would leave root's
// files in a directory this user then cannot clean up.
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'image-sbom-'));
const files = {
    status: '/var/lib/dpkg/status',
    osRelease: '/usr/lib/os-release',
    libves: '/usr/lib/libVES.so.1.0.0',
    ves: '/usr/bin/ves',
    localLib: '/usr/local/lib',   // liboqs.so.<version> and its soname link
};
const local = (k) => path.join(tmp, path.basename(files[k]));
let oqsFile;
const cid = dk(['create', image]).trim();
try {
    for (const p of Object.values(files)) {
        if (/[^A-Za-z0-9/._-]/.test(p + cid + tmp)) die(`unexpected characters in ${p} ${cid} ${tmp}`);
        run('bash', ['-o', 'pipefail', '-c', `${docker.join(' ')} cp ${cid}:${p} - | tar -xf - -C ${tmp}`]);
    }
} finally {
    dk(['rm', '-f', cid]);
}
for (const k of Object.keys(files)) if (!fs.existsSync(local(k))) die(`${files[k]} did not come out of the image`);
const localLib = fs.readdirSync(local('localLib'));
oqsFile = localLib.find((f) => /^liboqs\.so\.\d+\.\d+\.\d+$/.test(f));
if (!oqsFile) die(`no liboqs.so.X.Y.Z in /usr/local/lib (found: ${localLib.join(' ')})`);
const oqsVersion = oqsFile.replace(/^liboqs\.so\./, '');

const vesVersion = dk(['run', '--rm', image, '--version']);
const m = vesVersion.match(/^VES CLI (\S+) \(libVES\.c (\S+)\)/);
if (!m) die(`unexpected ves --version: ${vesVersion.trim()}`);
const [, cliVersion, libVersion] = m;
if (!version) version = libVersion;
else if (libVersion !== version) die(`ves says libVES.c ${libVersion}, the image label says ${version}`);
const kems = [...dk(['run', '--rm', image, '-Gl']).matchAll(/OQS:([A-Za-z0-9_-]+)/g)].map((x) => x[1]);
if (!kems.includes('ML-KEM-768')) die(`ves -Gl lists no ML-KEM-768 among its KEMs (${kems.join(' ') || 'none'})`);

// ---- liboqs: the upstream tag's commit, and the build options at the image's revision
const ls = run('git', ['ls-remote', 'https://github.com/open-quantum-safe/liboqs',
    `refs/tags/${oqsVersion}`, `refs/tags/${oqsVersion}^{}`]).trim().split('\n').filter(Boolean);
const peeled = ls.find((l) => l.endsWith('^{}')) || ls[0];
if (!peeled) die(`liboqs has no tag ${oqsVersion}`);
const oqsCommit = peeled.split('\t')[0];
const dockerfile = run('git', ['show', `${revision}:Dockerfile`]);
const oqsArg = (dockerfile.match(/^ARG LIBOQS_VERSION=(\S+)/m) || [])[1];
if (oqsArg !== oqsVersion) die(`the Dockerfile at ${revision} pins liboqs ${oqsArg}, the image has ${oqsVersion}`);
const oqsFlags = [...dockerfile.matchAll(/-D(OQS_[A-Z0-9_]+=[A-Z]+)/g)].map((x) => x[1]);

// ---- Debian packages
const osr = Object.fromEntries(fs.readFileSync(local('osRelease'), 'utf8').split('\n')
    .map((l) => l.match(/^([A-Z_]+)=("?)(.*)\2$/)).filter(Boolean).map((x) => [x[1], x[3]]));
const distro = `${osr.ID}-${osr.VERSION_ID}`;
const enc = (s) => encodeURIComponent(s);
const debs = fs.readFileSync(local('status'), 'utf8').split(/\n\n+/).map((para) => {
    const f = {};
    for (const l of para.split('\n')) {
        const mm = l.match(/^([A-Za-z-]+): (.*)$/);
        if (mm) f[mm[1]] = mm[2];
    }
    return f;
}).filter((f) => f.Package && f.Status === 'install ok installed').map((f) => {
    const src = f.Source ? f.Source.replace(/ \(.*\)$/, '') : null;
    const q = [`arch=${enc(f.Architecture)}`, `distro=${enc(distro)}`];
    if (src && src !== f.Package) q.push(`upstream=${enc(src)}`);
    const purl = `pkg:deb/${osr.ID}/${enc(f.Package)}@${enc(f.Version)}?${q.join('&')}`;
    const c = { 'bom-ref': purl, type: 'library', name: f.Package, version: f.Version, purl };
    if (src) c.properties = [{ name: 'libves:debian-source', value: f.Source }];
    return c;
}).sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
const deb = (name) => (debs.find((d) => d.name === name) || {})['bom-ref'];
for (const p of ['libssl3', 'libcurl4']) if (!deb(p)) die(`no installed ${p} among the image's ${debs.length} ${osr.ID} packages`);

// ---- the document
const imageRef = digest
    ? `pkg:oci/ves@${enc(digest)}?repository_url=${enc('docker.io/vesvault/ves')}&tag=${enc(version)}`
    : `image:${info.Id}`;
const libRef = `pkg:github/vesvault/libVES.c@v${version}`;
const cliRef = `ves@${cliVersion}`;
const oqsRef = `pkg:github/open-quantum-safe/liboqs@${oqsVersion}`;
const osRef = `os:${distro}`;
const hash = (file) => [{ alg: 'SHA-256', content: sha256(file) }];
const supplier = { name: 'VESvault Corp', url: ['https://vesvault.com'] };
// No image ID for a published image: its digest pins it, and the ID is not a
// property of the image but of the Docker reading it (the config digest with
// the classic image store, the manifest digest with containerd's), so it
// would make the same image's SBOM differ between machines.
const imageProps = [
    { name: 'libves:platform', value: `${info.Os}/${info.Architecture}` },
    { name: 'libves:revision', value: revision },
    { name: 'libves:base', value: osr.PRETTY_NAME },
];
if (!digest) imageProps.unshift({ name: 'libves:image-id', value: info.Id });
const imageComponent = digest ? {
    'bom-ref': imageRef, type: 'container', name: 'vesvault/ves', version, purl: imageRef, supplier,
    hashes: [{ alg: 'SHA-256', content: digest.replace(/^sha256:/, '') }],
    externalReferences: [
        { type: 'distribution', url: `https://hub.docker.com/r/vesvault/ves`, comment: `docker.io/vesvault/ves:${version}@${digest}` },
        { type: 'distribution', url: 'https://github.com/vesvault/libVES.c/pkgs/container/ves', comment: `ghcr.io/vesvault/ves:${version}@${digest}` },
        { type: 'vcs', url: 'https://github.com/vesvault/libVES.c' },
    ],
    properties: imageProps,
} : {
    'bom-ref': imageRef, type: 'container', name: 'vesvault/ves', version, supplier,
    externalReferences: [{ type: 'vcs', url: 'https://github.com/vesvault/libVES.c' }],
    properties: imageProps.concat([{ name: 'libves:unpublished',
        value: `${image}: built and never pushed, so it has no manifest digest and is named by its image ID` }]),
};
const bom = {
    bomFormat: 'CycloneDX',
    specVersion: '1.6',
    version: 1,
    metadata: {
        tools: { components: [{ type: 'application', name: 'libVES.c etc/image-sbom.js', version: revision }] },
        component: imageComponent,
    },
    components: [
        {
            'bom-ref': libRef, type: 'library', name: 'libVES.c', version, purl: libRef, supplier,
            licenses: [{ license: { id: 'Apache-2.0' } }],
            hashes: hash(local('libves')),
            externalReferences: [{ type: 'vcs', url: 'https://github.com/vesvault/libVES.c' }],
            pedigree: { commits: [{ uid: revision, url: `https://github.com/vesvault/libVES.c/commit/${revision}` }] },
            properties: [{ name: 'libves:path', value: files.libves }],
        },
        {
            'bom-ref': cliRef, type: 'application', name: 'ves', version: cliVersion, supplier,
            licenses: [{ license: { id: 'Apache-2.0' } }],
            hashes: hash(local('ves')),
            properties: [{ name: 'libves:path', value: files.ves }, { name: 'libves:source', value: `libVES.c ${version}` }],
        },
        {
            'bom-ref': oqsRef, type: 'library', name: 'liboqs', version: oqsVersion, purl: oqsRef,
            cpe: `cpe:2.3:a:openquantumsafe:liboqs:${oqsVersion}:*:*:*:*:*:*:*`,
            licenses: [{ license: { id: 'MIT' } }],
            hashes: hash(path.join(local('localLib'), oqsFile)),
            externalReferences: [{ type: 'vcs', url: 'https://github.com/open-quantum-safe/liboqs' }],
            pedigree: { commits: [{ uid: oqsCommit, url: `https://github.com/open-quantum-safe/liboqs/commit/${oqsCommit}` }] },
            properties: [
                { name: 'libves:path', value: `/usr/local/lib/${oqsFile}` },
                { name: 'libves:note', value: 'Built from source in the image (Dockerfile liboqs stage); not a Debian package' },
                { name: 'libves:build', value: oqsFlags.join(' ') },
                { name: 'libves:kems', value: kems.join(' ') },
            ],
        },
        { 'bom-ref': osRef, type: 'operating-system', name: osr.ID, version: osr.VERSION_ID, description: osr.PRETTY_NAME },
    ].concat(debs),
    dependencies: [
        { ref: imageRef, dependsOn: [cliRef, libRef, oqsRef, osRef] },
        { ref: cliRef, dependsOn: [libRef] },
        { ref: libRef, dependsOn: [oqsRef, deb('libssl3'), deb('libcurl4')].filter(Boolean) },
        { ref: osRef, dependsOn: debs.map((d) => d['bom-ref']) },
    ],
};
fs.rmSync(tmp, { recursive: true, force: true });
const id = crypto.createHash('sha256').update(JSON.stringify(bom)).digest('hex');
const uuid = `${id.slice(0, 8)}-${id.slice(8, 12)}-5${id.slice(13, 16)}-`
    + `${(8 | (parseInt(id[16], 16) & 3)).toString(16)}${id.slice(17, 20)}-${id.slice(20, 32)}`;
process.stdout.write(JSON.stringify(Object.assign({ bomFormat: bom.bomFormat, specVersion: bom.specVersion,
    serialNumber: `urn:uuid:${uuid}` }, bom), null, 2) + '\n');
process.stderr.write(`image-sbom: ${image} ${digest || `unpublished, ${info.Id}`}: libVES.c ${version} (${revision.slice(0, 7)}), ves ${cliVersion}, `
    + `liboqs ${oqsVersion} (${oqsCommit.slice(0, 7)}, ${kems.length} KEMs), ${debs.length} ${osr.ID} ${osr.VERSION_ID} packages\n`);
