# The victim host. Ubuntu + Wazuh agent + the tools the attack scenarios need.
# No auditd: the kernel audit subsystem is a single host-owned context and does
# not work per-container. Endpoint telemetry comes from Wazuh FIM (inotify) for
# file changes and Falco (eBPF) for process/syscall activity.
FROM ubuntu:24.04

ARG WAZUH_AGENT_VERSION=4.14.7-1
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
      curl gnupg lsb-release ca-certificates \
      python3 iproute2 iputils-ping netcat-openbsd openssh-client sshpass cron \
    && rm -rf /var/lib/apt/lists/*

# Wazuh agent repo + install (single download step)
RUN curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --dearmor -o /usr/share/keyrings/wazuh.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
       > /etc/apt/sources.list.d/wazuh.list \
    && apt-get update \
    && WAZUH_MANAGER="wazuh.manager" apt-get install -y wazuh-agent=${WAZUH_AGENT_VERSION} \
    && rm -rf /var/lib/apt/lists/*

COPY ossec.conf /var/ossec/etc/ossec.conf
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
