# Windeep v4 tools backend. The release workflow records the built image digest
# and bundle export carries the exact OCI image for offline reproduction.
FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive \
    PIPX_HOME=/opt/pipx \
    PIPX_BIN_DIR=/usr/local/bin

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      ca-certificates curl git python3 python3-pip pipx ruby-full default-jre-headless \
      nmap masscan tshark nikto sqlmap metasploit-framework wpscan radare2 \
      apktool jadx dex2jar \
 && rm -rf /var/lib/apt/lists/*

# Mobile tooling that is better isolated from the Windows host. Each install is
# explicit: a failed dependency makes the image build fail rather than silently
# advertising a tool that is not actually present.
RUN pipx install objection \
 && pipx install frida-tools \
 && pipx install apkleaks \
 && pipx install androguard \
 && pipx install drozer

# Stable command aliases used by catalog entries.
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
 && command -v r2 >/dev/null

WORKDIR /windeep/scratch
CMD ["/bin/bash"]
