
rm -f -- "${systemctl_path}"
fake_systemctl=$(mktemp)
cat > "${fake_systemctl}" <<'EOF'
#!/bin/bash
set -euo pipefail
printf '%s\n' "$*" >> /tmp/autostream-host-agent-systemctl.log
unit=${!#}
case "${1:-}" in
  daemon-reload)
    if [[ -e /tmp/autostream-host-agent-fail-daemon-reload ]]; then
      exit 94
    fi
    ;;
  is-active)
    if [[ ${unit} == autostream-host-self-update-recovery@?.timer ]]; then
      marker=/tmp/"${unit}".active
    elif [[ ${unit} == autostream-host-agent.service ]]; then
      marker=/tmp/autostream-host-agent-active
    else
      marker=/tmp/"${unit}".active
    fi
    if [[ ${unit} == autostream-host-agent.service &&
      -e /tmp/autostream-host-agent-is-active-query-error ]]; then
      exit 99
    fi
    if [[ ${unit} == autostream-host-agent.service &&
      -e /tmp/autostream-host-agent-final-active-check-fails ]]; then
      [[ " $* " == *" --quiet "* ]] || printf '%s\n' inactive
      exit 3
    fi
    if [[ -e ${marker} ]]; then
      [[ " $* " == *" --quiet "* ]] || printf '%s\n' active
      exit 0
    fi
    # A real systemd host can report an unloaded unit as stdout "inactive"
    # with exit status 4. Keep that exact pair in the root smoke fixture.
    [[ " $* " == *" --quiet "* ]] || printf '%s\n' inactive
    exit 4
    ;;
  is-enabled)
    if [[ ${unit} == autostream-host-self-update-recovery@?.timer ]]; then
      marker=/tmp/"${unit}".enabled
    elif [[ ${unit} == autostream-host-agent.service ]]; then
      marker=/tmp/autostream-host-agent-enabled
    else
      marker=/tmp/"${unit}".enabled
    fi
    if [[ -e ${marker} ]]; then
      [[ " $* " == *" --quiet "* ]] || printf '%s\n' enabled
      exit 0
    fi
    [[ " $* " == *" --quiet "* ]] || printf '%s\n' disabled
    exit 1
    ;;
  enable)
    if [[ ${unit} == autostream-host-self-update-recovery@?.timer ]]; then
      touch /tmp/"${unit}".enabled
      [[ " $* " != *" --now "* ]] || touch /tmp/"${unit}".active
      if [[ -e /tmp/autostream-host-agent-fail-timer-enable-after-side-effect ]]; then
        recovery_service=${unit/.timer/.service}
        touch /tmp/"${recovery_service}".active
        install -d -o root -g root -m 0755 \
          /opt/autostream/host-agent/slots/b/recovery-extra
        printf '%s\n' recovery-side-effect \
          > /opt/autostream/host-agent/slots/b/recovery-extra/ledger
        if [[ ${unit} == autostream-host-self-update-recovery@b.timer ]]; then
          exit 96
        fi
      fi
      exit 0
    fi
    if [[ ${unit} == autostream-host-agent.service ]]; then
      [[ -e /tmp/autostream-host-agent-allow-enable ]] || {
        printf 'prepare mode attempted forbidden service mutation: %s\n' "$*" >&2
        exit 92
      }
      touch /tmp/autostream-host-agent-enabled
      [[ " $* " != *" --now "* ]] || touch /tmp/autostream-host-agent-active
      if [[ -e /tmp/autostream-host-agent-fail-final-active-check ]]; then
        install -d -o autostream-host-agent -g autostream-host-agent -m 0700 \
          /var/lib/autostream-host-agent/runtime-created
        printf '%s\n' mutated \
          > /var/lib/autostream-host-agent/runtime-created/ledger
        touch /tmp/autostream-host-agent-final-active-check-fails
      fi
    else
      touch /tmp/"${unit}".enabled
      [[ " $* " != *" --now "* ]] || touch /tmp/"${unit}".active
    fi
    ;;
  start)
    if [[ ${unit} == autostream-host-agent.service ]]; then
      [[ -e /tmp/autostream-host-agent-allow-enable ]] || {
        printf 'prepare mode attempted forbidden service mutation: %s\n' "$*" >&2
        exit 92
      }
      touch /tmp/autostream-host-agent-active
    else
      if [[ ${unit} == autostream-local-executor.service ]]; then
        install -d -o root -g root -m 0700 /var/lib/autostream-local-executor
      fi
      touch /tmp/"${unit}".active
    fi
    ;;
  stop)
    if [[ ${unit} == autostream-host-agent.service ]]; then
      if [[ ! -e /tmp/autostream-host-agent-stop-keeps-active ]]; then
        rm -f -- /tmp/autostream-host-agent-active
      fi
      rm -f -- /tmp/autostream-host-agent-final-active-check-fails
    else
      rm -f -- /tmp/"${unit}".active
    fi
    ;;
  disable)
    if [[ ${unit} == autostream-host-self-update-recovery@?.timer ]]; then
      rm -f -- /tmp/"${unit}".enabled
      [[ " $* " != *" --now "* ]] || rm -f -- /tmp/"${unit}".active
      if [[ -e /tmp/autostream-host-agent-reactivate-recovery-after-timer-disable ]]; then
        recovery_service=${unit/.timer/.service}
        touch /tmp/"${recovery_service}".active
      fi
    elif [[ ${unit} == autostream-host-agent.service ]]; then
      rm -f -- /tmp/autostream-host-agent-enabled
      [[ " $* " != *" --now "* ]] || rm -f -- /tmp/autostream-host-agent-active
    else
      rm -f -- /tmp/"${unit}".enabled
      [[ " $* " != *" --now "* ]] || rm -f -- /tmp/"${unit}".active
    fi
    ;;
  *)
    exit 0
    ;;
esac
EOF
install -m 0755 "${fake_systemctl}" "${systemctl_path}"
rm -f -- "${fake_systemctl}"

tmpfiles_path=/usr/bin/systemd-tmpfiles
if [[ -e ${tmpfiles_path} ]]; then
  mv -- "${tmpfiles_path}" "${tmpfiles_path}.real"
fi
fake_tmpfiles=$(mktemp)
cat > "${fake_tmpfiles}" <<'EOF'
#!/bin/bash
set -euo pipefail
[[ ${1:-} == "--create" ]] || {
  printf 'unexpected systemd-tmpfiles invocation: %s\n' "$*" >&2
  exit 95
}
if [[ ${2:-} == "/etc/tmpfiles.d/autostream-local-executor.conf" ]]; then
  install -d -o root -g autostream-host-agent -m 0750 /run/autostream-local-executor
  install -d -o root -g root -m 0700 /run/autostream-updater
fi
EOF
install -m 0755 "${fake_tmpfiles}" "${tmpfiles_path}"
rm -f -- "${fake_tmpfiles}"
