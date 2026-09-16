# Windeep v4 tools backend. The release workflow records the built image digest
# and bundle export carries the exact OCI image for offline reproduction.
FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive \
    PIPX_HOME=/opt/pipx \
    PIPX_BIN_DIR=/usr/local/bin

# Source revisions are pinned so legacy/container-only tools do not drift between
# release builds. The Kali base image digest is captured by the release workflow.
ARG CMSMAP_REF=59dd0e2b3b0c751c6da2b0565374ab83c736b0e6
ARG GRAPHQLMAP_REF=59305d7570c8fbbb04a324e869ec9a196c150936
ARG SMUGGLER_REF=2be871e6151ce85167a277fab21c74c851d8b20b
ARG SSRFMAP_REF=290e07d75c52d68e021b6d0b4200c2a41ea20365
ARG TPLMAP_REF=616b0e527f62dd0930e6346ede6bef79e9bcf717
ARG QARK_VERSION=4.0.0

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      ca-certificates curl git python3 python3-pip python3-venv pipx ruby-full default-jre-headless \
      libcap2-bin cloud-enum \
      nmap masscan tshark nikto sqlmap metasploit-framework wpscan radare2 \
      apktool jadx dex2jar \
 && rm -rf /var/lib/apt/lists/*

# Hosted CI commonly runs containers with no-new-privileges. Kali's nmap payload
# may carry file capabilities, which makes exec(2) fail with EPERM in that mode.
# Strip file capabilities in the image; unprivileged connect scans remain usable,
# while callers that need raw scans can explicitly grant NET_RAW/NET_ADMIN.
RUN setcap -r /usr/lib/nmap/nmap 2>/dev/null || true

# Mobile tooling that is better isolated from the Windows host. Each install is
# explicit: a failed dependency makes the image build fail rather than silently
# advertising a tool that is not actually present.
RUN pipx install objection \
 && pipx install frida-tools \
 && pipx install apkleaks \
 && pipx install androguard \
 && pipx install drozer

# Older Python tools get independent environments. This prevents their dependency
# pins from contaminating the runtime used by newer mobile/security utilities.
RUN python3 -m venv /opt/tools/cmsmap \
 && /opt/tools/cmsmap/bin/pip install --no-cache-dir --upgrade pip \
 && /opt/tools/cmsmap/bin/pip install --no-cache-dir \
      "git+https://github.com/Dionach/CMSmap.git@${CMSMAP_REF}" \
 && ln -s /opt/tools/cmsmap/bin/cmsmap /usr/local/bin/cmsmap

RUN python3 -m venv /opt/tools/graphqlmap \
 && /opt/tools/graphqlmap/bin/pip install --no-cache-dir --upgrade pip \
 && /opt/tools/graphqlmap/bin/pip install --no-cache-dir \
      "git+https://github.com/swisskyrepo/GraphQLmap.git@${GRAPHQLMAP_REF}" \
 && ln -s /opt/tools/graphqlmap/bin/graphqlmap /usr/local/bin/graphqlmap

RUN python3 -m venv /opt/tools/qark \
 && /opt/tools/qark/bin/pip install --no-cache-dir --upgrade pip \
 && /opt/tools/qark/bin/pip install --no-cache-dir "qark==${QARK_VERSION}" \
 && ln -s /opt/tools/qark/bin/qark /usr/local/bin/qark

# Smuggler is a self-contained Python 3 source tool. Keep the checkout pinned and
# expose the stable catalog command through a tiny PATH shim.
RUN git clone --filter=blob:none https://github.com/defparam/smuggler.git /opt/smuggler \
 && git -C /opt/smuggler checkout --detach "${SMUGGLER_REF}" \
 && printf '#!/bin/sh\nexec python3 /opt/smuggler/smuggler.py "$@"\n' >/usr/local/bin/smuggler \
 && chmod +x /usr/local/bin/smuggler \
 && rm -rf /opt/smuggler/.git

# SSRFmap's current upstream requires Python >=3.12 and publishes a locked small
# runtime set. Install only those runtime dependencies into its own environment.
RUN git clone --filter=blob:none https://github.com/swisskyrepo/SSRFmap.git /opt/ssrfmap \
 && git -C /opt/ssrfmap checkout --detach "${SSRFMAP_REF}" \
 && python3 -m venv /opt/tools/ssrfmap \
 && /opt/tools/ssrfmap/bin/pip install --no-cache-dir --upgrade pip \
 && /opt/tools/ssrfmap/bin/pip install --no-cache-dir \
      dnslib==0.9.24 dnspython==2.6.1 Flask==3.0.3 requests==2.31.0 \
      tldextract==5.1.2 \
 && printf '#!/bin/sh\nexec /opt/tools/ssrfmap/bin/python /opt/ssrfmap/ssrfmap.py "$@"\n' >/usr/local/bin/ssrfmap \
 && chmod +x /usr/local/bin/ssrfmap \
 && rm -rf /opt/ssrfmap/.git

# tplmap is archived and its published dependency pins predate current Python.
# Preserve the pinned source revision but use API-compatible maintained runtime
# dependencies in an isolated venv so the CLI remains executable on Kali rolling.
RUN git clone --filter=blob:none https://github.com/epinna/tplmap.git /opt/tplmap \
 && git -C /opt/tplmap checkout --detach "${TPLMAP_REF}" \
 && python3 -m venv /opt/tools/tplmap \
 && /opt/tools/tplmap/bin/pip install --no-cache-dir --upgrade pip \
 && /opt/tools/tplmap/bin/pip install --no-cache-dir \
      PyYAML==6.0.2 certifi==2024.8.30 chardet==5.2.0 idna==3.10 \
      requests==2.32.3 urllib3==2.2.3 \
 && printf '#!/bin/sh\nexec /opt/tools/tplmap/bin/python /opt/tplmap/tplmap.py "$@"\n' >/usr/local/bin/tplmap \
 && chmod +x /usr/local/bin/tplmap \
 && rm -rf /opt/tplmap/.git

# Kali packages cloud-enum as `cloud_enum`; retain the catalog's historic
# `cloud_enum.py` command without special-casing the resolver or probe.
RUN printf '#!/bin/sh\nexec cloud_enum "$@"\n' >/usr/local/bin/cloud_enum.py \
 && chmod +x /usr/local/bin/cloud_enum.py

# Stable command aliases used by catalog entries. This list deliberately includes
# every command whose v4 route declares the shared container image.
RUN command -v frida >/dev/null \
 && command -v objection >/dev/null \
 && command -v apktool >/dev/null \
 && command -v jadx >/dev/null \
 && command -v d2j-dex2jar >/dev/null \
 && command -v nmap >/dev/null \
 && command -v masscan >/dev/null \
 && command -v tshark >/dev/null \
 && command -v nikto >/dev/null \
 && command -v sqlmap >/dev/null \
 && command -v msfconsole >/dev/null \
 && command -v wpscan >/dev/null \
 && command -v r2 >/dev/null \
 && command -v drozer >/dev/null \
 && command -v apkleaks >/dev/null \
 && command -v androguard >/dev/null \
 && command -v cloud_enum.py >/dev/null \
 && command -v cmsmap >/dev/null \
 && command -v graphqlmap >/dev/null \
 && command -v qark >/dev/null \
 && command -v smuggler >/dev/null \
 && command -v ssrfmap >/dev/null \
 && command -v tplmap >/dev/null

WORKDIR /windeep/scratch
CMD ["/bin/bash"]
