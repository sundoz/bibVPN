# Throwaway "VPS": Ubuntu 24.04 with systemd and sshd, for testing the Ansible deploy.
FROM ubuntu:24.04
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y systemd systemd-sysv openssh-server python3 sudo iproute2 kmod && rm -f /etc/ssh/sshd_config.d/* && systemctl enable ssh
RUN mkdir -p /root/.ssh && chmod 700 /root/.ssh
CMD ["/sbin/init"]
