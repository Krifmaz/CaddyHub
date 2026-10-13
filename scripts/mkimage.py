#!/usr/bin/env python3
"""Builds Caddymium's container images without Docker.

Pulls the base image layers from Docker Hub, adds one layer with our files,
and writes a tar in `docker save` format that `docker load` (and Portainer's
Images → Import) accepts. Used when no machine with Docker is at hand.

  mkimage.py panel  --binary caddymium --out caddymium.tar [--tag ghcr.io/krifmaz/caddymium:latest]
  mkimage.py caddy  --binary caddy --entrypoint caddy/entrypoint.sh --out caddymium-caddy.tar
"""

import argparse
import gzip
import hashlib
import io
import json
import os
import sys
import tarfile
import time
import urllib.request

HUB = "https://registry-1.docker.io"
ACCEPT = ", ".join(
    [
        "application/vnd.docker.distribution.manifest.list.v2+json",
        "application/vnd.oci.image.index.v1+json",
        "application/vnd.docker.distribution.manifest.v2+json",
        "application/vnd.oci.image.manifest.v1+json",
    ]
)


def log(msg):
    print(msg, file=sys.stderr, flush=True)


def get(url, headers=None, raw=False):
    req = urllib.request.Request(url, headers=headers or {})
    with urllib.request.urlopen(req, timeout=120) as r:
        data = r.read()
    return data if raw else json.loads(data)


def hub_token(repo):
    return get(f"https://auth.docker.io/token?service=registry.docker.io&scope=repository:{repo}:pull")["token"]


def sha256(b):
    return hashlib.sha256(b).hexdigest()


def fetch_base(repo, tag, arch="amd64", cache=None):
    """Returns (config_dict, [uncompressed layer tar bytes]) for a Docker Hub image."""
    cache = cache or os.environ.get("MKIMAGE_CACHE") or os.path.join(os.path.expanduser("~"), "caddymium-build", "base-cache")
    os.makedirs(cache, exist_ok=True)
    tok = hub_token(repo)
    h = {"Authorization": f"Bearer {tok}", "Accept": ACCEPT}
    m = get(f"{HUB}/v2/{repo}/manifests/{tag}", h)
    if "manifests" in m:  # multi-arch index: pick linux/arch
        digest = None
        for e in m["manifests"]:
            p = e.get("platform", {})
            if p.get("os") == "linux" and p.get("architecture") == arch:
                digest = e["digest"]
                break
        if not digest:
            raise SystemExit(f"{repo}:{tag} has no linux/{arch} manifest")
        m = get(f"{HUB}/v2/{repo}/manifests/{digest}", h)
    cfg_digest = m["config"]["digest"]
    cfg = json.loads(get(f"{HUB}/v2/{repo}/blobs/{cfg_digest}", h, raw=True))
    layers = []
    for i, l in enumerate(m["layers"]):
        d = l["digest"]
        path = os.path.join(cache, d.replace(":", "_") + ".tar")
        if os.path.exists(path):
            data = open(path, "rb").read()
        else:
            log(f"  fetching {repo} layer {i + 1}/{len(m['layers'])} ({l['size'] >> 10} KB)")
            blob = get(f"{HUB}/v2/{repo}/blobs/{d}", h, raw=True)
            data = gzip.decompress(blob) if "gzip" in l["mediaType"] else blob
            open(path, "wb").write(data)
        want = cfg["rootfs"]["diff_ids"][i]
        got = "sha256:" + sha256(data)
        if want != got:
            raise SystemExit(f"layer {d}: diff_id mismatch ({got} != {want})")
        layers.append(data)
    log(f"  {repo}:{tag} -> {len(layers)} layer(s), config {cfg_digest[7:19]}")
    return cfg, layers


def read_from_layers(layers, name):
    """Returns the last version of a file across base layers (e.g. etc/passwd)."""
    data = None
    for raw in layers:
        with tarfile.open(fileobj=io.BytesIO(raw)) as t:
            try:
                f = t.extractfile(name)
                if f:
                    data = f.read()
            except KeyError:
                pass
    return data


class Layer:
    """Builds one uncompressed layer tar with explicit ownership and modes."""

    def __init__(self):
        self.buf = io.BytesIO()
        self.tar = tarfile.open(fileobj=self.buf, mode="w", format=tarfile.GNU_FORMAT)
        self.now = int(time.time())

    def dir(self, path, mode=0o755, uid=0, gid=0):
        ti = tarfile.TarInfo(path.strip("/"))
        ti.type = tarfile.DIRTYPE
        ti.mode, ti.uid, ti.gid, ti.mtime = mode, uid, gid, self.now
        self.tar.addfile(ti)

    def file(self, path, data, mode=0o644, uid=0, gid=0):
        ti = tarfile.TarInfo(path.strip("/"))
        ti.size, ti.mode, ti.uid, ti.gid, ti.mtime = len(data), mode, uid, gid, self.now
        self.tar.addfile(ti, io.BytesIO(data))

    def bytes(self):
        self.tar.close()
        return self.buf.getvalue()


def write_image(out, tag, base_cfg, base_layers, new_layer, config, history_note):
    """Writes a docker-save style tar."""
    layers = base_layers + [new_layer]
    cfg = {
        "architecture": base_cfg.get("architecture", "amd64"),
        "os": "linux",
        "created": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "config": config,
        "rootfs": {"type": "layers", "diff_ids": ["sha256:" + sha256(l) for l in layers]},
        "history": base_cfg.get("history", []) + [{"created": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "created_by": history_note}],
    }
    cfg_bytes = json.dumps(cfg, separators=(",", ":")).encode()
    cfg_name = sha256(cfg_bytes) + ".json"
    layer_paths = []
    with tarfile.open(out, "w") as t:
        def add(name, data):
            ti = tarfile.TarInfo(name)
            ti.size = len(data)
            ti.mtime = int(time.time())
            t.addfile(ti, io.BytesIO(data))

        for l in layers:
            lid = sha256(l)
            layer_paths.append(f"{lid}/layer.tar")
            add(f"{lid}/layer.tar", l)
        add(cfg_name, cfg_bytes)
        manifest = [{"Config": cfg_name, "RepoTags": [tag], "Layers": layer_paths}]
        add("manifest.json", json.dumps(manifest, separators=(",", ":")).encode())
    log(f"wrote {out} ({os.path.getsize(out) >> 20} MB, tag {tag})")


def build_panel(a):
    log("base: alpine:3")
    base_cfg, base_layers = fetch_base("library/alpine", "3")
    binary = open(a.binary, "rb").read()
    log("  CA bundle")
    cacert = get("https://curl.se/ca/cacert.pem", raw=True)
    passwd = read_from_layers(base_layers, "etc/passwd") or b""
    group = read_from_layers(base_layers, "etc/group") or b""
    if b"caddymium:" not in passwd:
        passwd += b"caddymium:x:1000:1000:Linux User,,,:/data:/sbin/nologin\n"
    if b"caddymium:" not in group:
        group += b"caddymium:x:1000:\n"
    L = Layer()
    L.file("etc/passwd", passwd, 0o644)
    L.file("etc/group", group, 0o644)
    L.dir("etc/ssl")
    L.dir("etc/ssl/certs")
    L.file("etc/ssl/certs/ca-certificates.crt", cacert, 0o644)
    L.dir("usr/local")
    L.dir("usr/local/bin")
    L.file("usr/local/bin/caddymium", binary, 0o755)
    L.dir("data", 0o700, 1000, 1000)
    base_env = base_cfg.get("config", {}).get("Env") or ["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"]
    config = {
        "User": "caddymium",
        "Env": base_env,
        "Entrypoint": ["caddymium"],
        "Cmd": None,
        "WorkingDir": "/data",
        "ExposedPorts": {"8080/tcp": {}},
        "Volumes": {"/data": {}},
        "Healthcheck": {"Test": ["CMD", "caddymium", "-healthcheck"], "Interval": 30_000_000_000, "Timeout": 5_000_000_000, "StartPeriod": 10_000_000_000},
        "Labels": {"org.opencontainers.image.source": "https://github.com/Krifmaz/Caddymium", "org.opencontainers.image.version": a.version},
    }
    write_image(a.out, a.tag, base_cfg, base_layers, L.bytes(), config, f"Caddymium panel {a.version} (mkimage.py)")


def build_caddy(a):
    log("base: caddy:2-alpine")
    base_cfg, base_layers = fetch_base("library/caddy", "2-alpine")
    binary = open(a.binary, "rb").read()
    entry = open(a.entrypoint, "rb").read().replace(b"\r\n", b"\n")
    L = Layer()
    L.dir("usr/bin")
    L.file("usr/bin/caddy", binary, 0o755)
    L.dir("usr/local")
    L.dir("usr/local/bin")
    L.file("usr/local/bin/caddymium-entrypoint", entry, 0o755)
    bc = dict(base_cfg.get("config", {}))
    config = {
        "Env": bc.get("Env"),
        "Entrypoint": ["/usr/local/bin/caddymium-entrypoint"],
        "Cmd": None,
        "WorkingDir": bc.get("WorkingDir", "/srv"),
        "ExposedPorts": bc.get("ExposedPorts", {"80/tcp": {}, "443/tcp": {}, "443/udp": {}, "2019/tcp": {}}),
        "Volumes": bc.get("Volumes"),
        "Labels": {"org.opencontainers.image.source": "https://github.com/Krifmaz/Caddymium", "org.opencontainers.image.version": a.version},
    }
    write_image(a.out, a.tag, base_cfg, base_layers, L.bytes(), config, f"Caddymium caddy {a.version} (mkimage.py)")


def push(a):
    """Pushes a docker-save tar to a registry (ghcr.io) with the HTTP API.

    Credentials come from GHCR_USER and GHCR_TOKEN (a token with the
    write:packages scope). Layers are gzipped on the way up.
    """
    user, token = os.environ.get("GHCR_USER", ""), os.environ.get("GHCR_TOKEN", "")
    if not user or not token:
        raise SystemExit("set GHCR_USER and GHCR_TOKEN (a GitHub token with write:packages)")
    with tarfile.open(a.tar) as t:
        manifest = json.load(t.extractfile("manifest.json"))[0]
        cfg_bytes = t.extractfile(manifest["Config"]).read()
        layers = [t.extractfile(l).read() for l in manifest["Layers"]]
    ref = a.ref or manifest["RepoTags"][0]
    host, path = ref.split("/", 1)
    repo, tag = path.rsplit(":", 1) if ":" in path else (path, "latest")
    import base64
    basic = base64.b64encode(f"{user}:{token}".encode()).decode()
    tok = get(f"https://{host}/token?scope=repository:{repo}:pull,push&service={host}", {"Authorization": f"Basic {basic}"})["token"]
    H = {"Authorization": f"Bearer {tok}"}
    base = f"https://{host}/v2/{repo}"

    def req(method, url, data=None, headers=None):
        r = urllib.request.Request(url, data=data, method=method, headers={**H, **(headers or {})})
        try:
            with urllib.request.urlopen(r, timeout=600) as resp:
                return resp.status, dict(resp.headers), resp.read()
        except urllib.error.HTTPError as e:
            return e.code, dict(e.headers), e.read()

    def upload(blob, digest, what):
        st, _, _ = req("HEAD", f"{base}/blobs/{digest}")
        if st == 200:
            log(f"  {what} {digest[7:19]} already present")
            return
        st, h, body = req("POST", f"{base}/blobs/uploads/")
        if st not in (202,):
            raise SystemExit(f"start upload failed: {st} {body[:200]!r}")
        loc = h.get("Location") or h.get("location")
        if loc.startswith("/"):
            loc = f"https://{host}{loc}"
        sep = "&" if "?" in loc else "?"
        st, _, body = req("PUT", f"{loc}{sep}digest={digest}", blob, {"Content-Type": "application/octet-stream", "Content-Length": str(len(blob))})
        if st not in (201, 204):
            raise SystemExit(f"upload of {what} failed: {st} {body[:200]!r}")
        log(f"  {what} {digest[7:19]} uploaded ({len(blob) >> 20} MB)")

    layer_descs = []
    for i, l in enumerate(layers):
        gz = gzip.compress(l, compresslevel=6)
        d = "sha256:" + sha256(gz)
        upload(gz, d, f"layer {i + 1}/{len(layers)}")
        layer_descs.append({"mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip", "size": len(gz), "digest": d})
    cfg_digest = "sha256:" + sha256(cfg_bytes)
    upload(cfg_bytes, cfg_digest, "config")
    man = {
        "schemaVersion": 2,
        "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
        "config": {"mediaType": "application/vnd.docker.container.image.v1+json", "size": len(cfg_bytes), "digest": cfg_digest},
        "layers": layer_descs,
    }
    body = json.dumps(man, separators=(",", ":")).encode()
    st, h, resp = req("PUT", f"{base}/manifests/{tag}", body, {"Content-Type": man["mediaType"]})
    if st not in (201,):
        raise SystemExit(f"manifest push failed: {st} {resp[:300]!r}")
    log(f"pushed {ref} ({h.get('Docker-Content-Digest') or h.get('docker-content-digest')})")


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("kind", choices=["panel", "caddy", "push"])
    p.add_argument("--binary")
    p.add_argument("--entrypoint", default="caddy/entrypoint.sh")
    p.add_argument("--out")
    p.add_argument("--tag")
    p.add_argument("--version", default="local")
    p.add_argument("--tar", help="push: the docker-save tar to upload")
    p.add_argument("--ref", help="push: registry/repo:tag (default: the tar's RepoTags)")
    a = p.parse_args()
    if a.kind == "push":
        if not a.tar:
            raise SystemExit("push needs --tar")
        return push(a)
    if not a.binary or not a.out:
        raise SystemExit(f"{a.kind} needs --binary and --out")
    if not a.tag:
        a.tag = "ghcr.io/krifmaz/caddymium:latest" if a.kind == "panel" else "ghcr.io/krifmaz/caddymium-caddy:latest"
    (build_panel if a.kind == "panel" else build_caddy)(a)


if __name__ == "__main__":
    main()
