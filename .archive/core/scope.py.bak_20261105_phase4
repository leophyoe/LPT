"""Scope authorization, engagement lifecycle guard, and target validation service.

Enforces strict boundaries before any network scan or assessment tool
is allowed to execute against an IP, CIDR subnet, or hostname.
Guarantees fail-closed semantics for excluded targets, expired authorizations,
and non-active engagement lifecycles.
"""

from __future__ import annotations

import ipaddress
import re
import socket
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from storage.models import (
    Project,
    ProjectStatus,
    ScopeRuleType,
    TargetScope,
    TargetType,
)


@dataclass
class ScopeCheckResult:
    is_allowed: bool
    reason: str
    matched_scope: Optional[TargetScope] = None

    def __iter__(self):
        yield self.is_allowed
        yield self.reason


class ScopeAuthorizationService:
    """Validates targets against engagement authorization rules and scope boundaries."""

    @staticmethod
    def _is_valid_hostname(hostname: str) -> bool:
        """Validates that a string conforms to RFC 1123 hostname rules."""
        if not hostname or not isinstance(hostname, str) or len(hostname) > 253:
            return False
        # Remove trailing dot if present (FQDN)
        h = hostname[:-1] if hostname.endswith(".") else hostname
        allowed = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$")
        labels = h.split(".")
        if not labels or any(not label for label in labels):
            return False
        return all(bool(allowed.match(label)) for label in labels)

    @classmethod
    def _extract_host_or_ip(cls, raw_target: str) -> str:
        """Clean and extract host, IP, or CIDR from URLs, host:port, or network strings.

        Guarantees fail-closed semantics: returns an empty string for invalid,
        malformed, empty, or ambiguous inputs.
        """
        if not raw_target or not isinstance(raw_target, str):
            return ""
        target = raw_target.strip()
        if not target:
            return ""

        # 1. URL parsing (if scheme present or starts with //)
        if "://" in target or target.startswith("//"):
            try:
                parsed = urlparse(target)
                scheme = (parsed.scheme or "").lower()
                if scheme and scheme not in ("http", "https"):
                    return ""
                target = parsed.hostname or ""
            except Exception:
                return ""
            if not target:
                return ""

        # 2. Bracketed IPv6 handling: e.g. [2001:db8::1]:8080 or [2001:db8::1] or [2001:db8::1]/path
        bracket_match = re.match(r"^\[([0-9a-fA-F:]+)\](?::\d+)?(?:/.*)?$", target)
        if bracket_match:
            ipv6_candidate = bracket_match.group(1)
            try:
                ipaddress.IPv6Address(ipv6_candidate)
                return ipv6_candidate
            except ValueError:
                return ""

        # 3. Path / query stripping if target contains slashes but is NOT a CIDR notation
        if "/" in target:
            parts = target.split("/", 1)
            # Check if this is a CIDR network mask (e.g. /24, /64, /128)
            if parts[1].isdigit():
                # Potential CIDR
                try:
                    ipaddress.ip_network(target, strict=False)
                    return target
                except ValueError:
                    return ""
            else:
                # Target has a path or query suffix without scheme (e.g. example.com/login)
                target = parts[0]

        # 4. Host:port or IPv4:port handling
        if ":" in target:
            # If multiple colons, it might be raw IPv6 (e.g. 2001:db8::1)
            if target.count(":") > 1:
                try:
                    ipaddress.IPv6Address(target)
                    return target
                except ValueError:
                    return ""
            else:
                # Exactly one colon: host:port or ipv4:port
                parts = target.split(":")
                if len(parts) == 2 and parts[1].isdigit():
                    target = parts[0]
                else:
                    return ""

        # 5. Wildcard domain handling: e.g. *.example.com
        if target.startswith("*."):
            base_domain = target[2:]
            if cls._is_valid_hostname(base_domain):
                return target
            return ""

        # 6. Final validation: Is target a valid IPv4, IPv6, CIDR, or Hostname?
        try:
            ipaddress.ip_address(target)
            return target
        except ValueError:
            pass

        try:
            ipaddress.ip_network(target, strict=False)
            return target
        except ValueError:
            pass

        if cls._is_valid_hostname(target):
            return target

        return ""

    @staticmethod
    def _extract_port(raw_target: str) -> Optional[int]:
        """Extract explicit port number from URL or host:port string."""
        if not raw_target or not isinstance(raw_target, str):
            return None
        target = raw_target.strip()
        if not target:
            return None

        # Check bracketed IPv6 with port: e.g. [2001:db8::1]:8080
        bracket_port = re.match(r"^\[[0-9a-fA-F:]+\]:(\d+)", target)
        if bracket_port:
            try:
                p = int(bracket_port.group(1))
                return p if 1 <= p <= 65535 else None
            except ValueError:
                return None

        if "://" in target:
            try:
                parsed = urlparse(target)
                if parsed.port:
                    return parsed.port
                return 443 if parsed.scheme == "https" else (80 if parsed.scheme == "http" else None)
            except Exception:
                return None
        elif ":" in target and not target.endswith("]"):
            parts = target.split(":")
            if len(parts) == 2 and parts[1].isdigit():
                try:
                    p = int(parts[1])
                    return p if 1 <= p <= 65535 else None
                except ValueError:
                    return None
        return None

    @classmethod
    def validate_engagement_lifecycle(cls, project: Optional[Project]) -> tuple[bool, str]:
        """Validates engagement status and date window fail-closed."""
        if not project:
            return False, "No active engagement project selected."
        if project.status != ProjectStatus.ACTIVE:
            status_label = project.status.value.replace("_", " ").title()
            return (
                False,
                f"Engagement '{project.name}' is in '{status_label}' status. Active authorization is required to perform assessments.",
            )

        now = datetime.now(timezone.utc)
        if project.end_date and project.end_date.strip():
            end_val = project.end_date.strip()
            try:
                end_dt = cls._parse_engagement_datetime(end_val, end_of_day=True)
            except ValueError:
                return False, f"Invalid engagement end date '{end_val}'; authorization is blocked."
            if now > end_dt:
                return False, f"Engagement testing authorization window expired at {end_val}."

        if project.start_date and project.start_date.strip():
            start_val = project.start_date.strip()
            try:
                start_dt = cls._parse_engagement_datetime(start_val)
            except ValueError:
                return False, f"Invalid engagement start date '{start_val}'; authorization is blocked."
            if now < start_dt:
                return False, f"Engagement testing window has not started yet (begins {start_val})."

        return True, "Engagement lifecycle is active and valid."

    @classmethod
    def is_target_authorized(
        cls,
        target: str,
        scopes: List[TargetScope],
        project: Optional[Project] = None,
        resolve_dns: bool = False,
    ) -> ScopeCheckResult:
        """Verify if a target is authorized, respecting exclusions, RoE, and engagement lifecycle."""
        # 1. Lifecycle State Machine Guard: Fail-Closed if not active
        if project:
            lifecycle_ok, lifecycle_msg = cls.validate_engagement_lifecycle(project)
            if not lifecycle_ok:
                return ScopeCheckResult(is_allowed=False, reason=lifecycle_msg)

        if not scopes:
            return ScopeCheckResult(
                is_allowed=False,
                reason="No authorized target scopes defined for this project.",
            )

        if not target or not isinstance(target, str) or not target.strip():
            return ScopeCheckResult(
                is_allowed=False,
                reason="Target is empty or missing; failed closed.",
            )

        clean_target = cls._extract_host_or_ip(target)
        if not clean_target:
            return ScopeCheckResult(
                is_allowed=False,
                reason=f"Target '{target}' is malformed or invalid; failed closed.",
            )

        target_port = cls._extract_port(target)

        # Check if the target is an IP network (CIDR) or single IP address
        target_net = None
        target_ip = None
        is_ip = False
        is_net = False

        if "/" in clean_target:
            try:
                target_net = ipaddress.ip_network(clean_target, strict=False)
                is_net = True
                is_ip = True
            except ValueError:
                pass
        if not is_net:
            try:
                target_ip = ipaddress.ip_address(clean_target)
                is_ip = True
            except ValueError:
                target_ip = None
                is_ip = False

        # Partition scopes into active exclusions and inclusions
        now = datetime.now(timezone.utc)
        valid_scopes: List[TargetScope] = []
        for s in scopes:
            # Check individual scope start date / effective_from
            if getattr(s, "effective_from", None) and s.effective_from.strip():
                try:
                    start_time = cls._parse_engagement_datetime(s.effective_from.strip())
                    if now < start_time:
                        continue
                except ValueError:
                    continue

            # Check individual scope expiration
            if s.expires_at and s.expires_at.strip():
                try:
                    expiry = cls._parse_engagement_datetime(s.expires_at.strip(), end_of_day=True)
                except ValueError:
                    # An invalid expiry must never turn an expiring rule into an
                    # active authorization or exclusion.
                    continue
                if expiry < now:
                    continue
            valid_scopes.append(s)

        excluded_scopes = [
            s for s in valid_scopes
            if s.rule_type == ScopeRuleType.EXCLUDED or not s.is_authorized
        ]
        allowed_scopes = [
            s for s in valid_scopes
            if s.rule_type == ScopeRuleType.ALLOWED and s.is_authorized
        ]

        # 3. EXCLUSION CHECK (Strict Precedence: Exclusions ALWAYS override inclusions)
        for ex in excluded_scopes:
            ex_clean = cls._extract_host_or_ip(ex.target)
            if not ex_clean:
                continue
            if is_ip:
                try:
                    ex_net = ipaddress.ip_network(ex_clean, strict=False)
                    if is_net and target_net:
                        if target_net.version == ex_net.version and target_net.overlaps(ex_net):
                            return ScopeCheckResult(
                                is_allowed=False,
                                reason=f"Target network {clean_target} overlaps with EXCLUDED scope network {ex.target}.",
                                matched_scope=ex,
                            )
                    elif target_ip:
                        if target_ip.version == ex_net.version and target_ip in ex_net:
                            return ScopeCheckResult(
                                is_allowed=False,
                                reason=f"Target {clean_target} matches EXCLUDED scope network {ex.target}.",
                                matched_scope=ex,
                            )
                except (ValueError, TypeError):
                    pass
            else:
                if clean_target.lower() == ex_clean.lower():
                    return ScopeCheckResult(
                        is_allowed=False,
                        reason=f"Target {clean_target} matches explicitly EXCLUDED host {ex.target}.",
                        matched_scope=ex,
                    )
                if ex_clean.startswith("*."):
                    domain_suffix = ex_clean[2:].lower()
                    host = clean_target.lower().rstrip(".")
                    if host == domain_suffix or host.endswith("." + domain_suffix):
                        return ScopeCheckResult(
                            is_allowed=False,
                            reason=f"Target {clean_target} matches EXCLUDED domain pattern {ex.target}.",
                            matched_scope=ex,
                        )

        # 4. Optional Pre-Execution DNS Resolution Guard
        if resolve_dns and not is_ip:
            try:
                resolved_ips = {
                    item[4][0] for item in socket.getaddrinfo(clean_target, None, socket.AF_UNSPEC)
                }
                for r_ip_str in resolved_ips:
                    r_ip = ipaddress.ip_address(r_ip_str)
                    for ex in excluded_scopes:
                        ex_clean = cls._extract_host_or_ip(ex.target)
                        try:
                            ex_net = ipaddress.ip_network(ex_clean, strict=False)
                            if r_ip in ex_net:
                                return ScopeCheckResult(
                                    is_allowed=False,
                                    reason=f"Target {clean_target} resolves to {r_ip_str}, which matches EXCLUDED scope {ex.target}.",
                                    matched_scope=ex,
                                )
                        except ValueError:
                            pass
            except (OSError, socket.gaierror) as exc:
                # Fail closed: DNS cannot prove the hostname avoids excluded IPs.
                return ScopeCheckResult(
                    is_allowed=False,
                    reason=f"Could not resolve {clean_target} to verify excluded network ranges: {exc}",
                )

        # Validate any explicit port restriction before choosing among overlapping
        # allowed rules. An unrestricted broad rule must not shadow a narrower rule.
        matching_port_scope = None
        for scope in allowed_scopes:
            scope_clean = cls._extract_host_or_ip(scope.target)
            matched = False
            if is_ip:
                try:
                    scope_net = ipaddress.ip_network(scope_clean, strict=False)
                    if is_net and target_net:
                        matched = (target_net.version == scope_net.version and target_net.subnet_of(scope_net))
                    elif target_ip:
                        matched = (target_ip.version == scope_net.version and target_ip in scope_net)
                except (ValueError, TypeError):
                    continue
            else:
                host = clean_target.lower().rstrip(".")
                pattern = scope_clean.lower().rstrip(".")
                matched = host == pattern or (
                    pattern.startswith("*.")
                    and host != pattern[2:]
                    and host.endswith("." + pattern[2:])
                )
            if matched:
                matching_port_scope = scope
                if scope.ports_allowed and scope.ports_allowed.strip():
                    port_check = cls._check_ports(target_port, scope.ports_allowed)
                    if not port_check[0]:
                        return ScopeCheckResult(False, port_check[1], scope)

        if target_port is not None and matching_port_scope is None:
            return ScopeCheckResult(
                False,
                f"Port {target_port} is not authorized by any matching target scope.",
            )

        # 5. INCLUSION CHECK
        for scope in allowed_scopes:
            scope_clean = cls._extract_host_or_ip(scope.target)

            # Match IP or CIDR network
            if is_ip:
                try:
                    scope_net = ipaddress.ip_network(scope_clean, strict=False)
                    matched_net = False
                    if is_net and target_net:
                        if target_net.version == scope_net.version and target_net.subnet_of(scope_net):
                            matched_net = True
                    elif target_ip and target_ip in scope_net:
                        if target_ip.version == scope_net.version:
                            matched_net = True

                    if matched_net:
                        port_check = cls._check_ports(target_port, scope.ports_allowed)
                        if not port_check[0]:
                            return ScopeCheckResult(is_allowed=False, reason=port_check[1], matched_scope=scope)
                        return ScopeCheckResult(
                            is_allowed=True,
                            reason=f"Target {clean_target} falls within authorized network {scope.target}.",
                            matched_scope=scope,
                        )
                except ValueError:
                    pass

            # Match exact hostname or wildcard domain
            if not is_ip:
                if clean_target.lower() == scope_clean.lower():
                    port_check = cls._check_ports(target_port, scope.ports_allowed)
                    if not port_check[0]:
                        return ScopeCheckResult(is_allowed=False, reason=port_check[1], matched_scope=scope)
                    return ScopeCheckResult(
                        is_allowed=True,
                        reason=f"Target {clean_target} matches authorized host {scope.target}.",
                        matched_scope=scope,
                    )
                # Wildcard support, e.g. *.example.com or .example.com
                if scope_clean.startswith("*."):
                    domain_suffix = scope_clean[2:].lower()
                    host = clean_target.lower().rstrip(".")
                    if host != domain_suffix and host.endswith("." + domain_suffix):
                        port_check = cls._check_ports(target_port, scope.ports_allowed)
                        if not port_check[0]:
                            return ScopeCheckResult(is_allowed=False, reason=port_check[1], matched_scope=scope)
                        return ScopeCheckResult(
                            is_allowed=True,
                            reason=f"Target {clean_target} matches domain pattern {scope.target}.",
                            matched_scope=scope,
                        )

        return ScopeCheckResult(
            is_allowed=False,
            reason=f"Target '{clean_target}' is NOT in the authorized scope list.",
        )

    @staticmethod
    def _check_ports(port: Optional[int], ports_allowed: str) -> tuple[bool, str]:
        """Validates port if ports_allowed is configured."""
        if not ports_allowed or not ports_allowed.strip() or port is None:
            return True, ""

        allowed_set = set()
        for token in ports_allowed.split(","):
            token = token.strip()
            if "-" in token:
                try:
                    if token.count("-") != 1:
                        continue
                    start_p, end_p = map(int, token.split("-"))
                    if not (1 <= start_p <= end_p <= 65535):
                        continue
                    allowed_set.update(range(start_p, end_p + 1))
                except ValueError:
                    pass
            elif token.isdigit():
                value = int(token)
                if 1 <= value <= 65535:
                    allowed_set.add(value)

        if port not in allowed_set:
            return False, f"Port {port} is not in the authorized ports list ({ports_allowed})."
        return True, ""

    @staticmethod
    def _parse_engagement_datetime(value: str, end_of_day: bool = False) -> datetime:
        """Parse an ISO date or datetime into timezone-aware UTC."""
        try:
            if len(value) == 10:
                parsed = datetime.fromisoformat(value)
                if parsed.date().isoformat() != value:
                    raise ValueError(f"Invalid ISO date: {value}")
                if end_of_day:
                    parsed = parsed.replace(hour=23, minute=59, second=59, microsecond=999999)
            else:
                parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError(f"Invalid ISO date/datetime: {value}") from exc
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)

    @classmethod
    def detect_scope_conflicts(cls, scopes: List[TargetScope]) -> List[Dict[str, Any]]:
        """Identifies overlaps between allowed scopes and excluded scopes."""
        conflicts = []
        allowed = [s for s in scopes if s.rule_type == ScopeRuleType.ALLOWED and s.is_authorized]
        excluded = [s for s in scopes if s.rule_type == ScopeRuleType.EXCLUDED or not s.is_authorized]

        for a in allowed:
            a_clean = cls._extract_host_or_ip(a.target)
            for ex in excluded:
                ex_clean = cls._extract_host_or_ip(ex.target)
                # 1. CIDR contains excluded IP or subnet
                try:
                    a_net = ipaddress.ip_network(a_clean, strict=False)
                    try:
                        ex_ip = ipaddress.ip_address(ex_clean)
                        if ex_ip in a_net:
                            conflicts.append({
                                "allowed_scope": a,
                                "excluded_scope": ex,
                                "type": "subnet_contains_excluded_ip",
                                "message": f"Allowed CIDR '{a.target}' contains Excluded IP '{ex.target}'. Excluded IP will be blocked.",
                            })
                    except ValueError:
                        try:
                            ex_net = ipaddress.ip_network(ex_clean, strict=False)
                            if ex_net.subnet_of(a_net):
                                conflicts.append({
                                    "allowed_scope": a,
                                    "excluded_scope": ex,
                                    "type": "subnet_contains_excluded_subnet",
                                    "message": f"Allowed CIDR '{a.target}' contains Excluded Subnet '{ex.target}'.",
                                })
                        except ValueError:
                            pass
                except ValueError:
                    pass

                # 2. Wildcard domain contains excluded host
                if a_clean.startswith("*."):
                    suffix = a_clean[1:].lower()
                    if ex_clean.lower().endswith(suffix) and ex_clean.lower() != a_clean.lower():
                        conflicts.append({
                            "allowed_scope": a,
                            "excluded_scope": ex,
                            "type": "wildcard_contains_excluded_host",
                            "message": f"Allowed pattern '{a.target}' covers Excluded host '{ex.target}'. Excluded host will be blocked.",
                        })

        return conflicts

    @classmethod
    def validate_web_redirect(
        cls,
        initial_url: str,
        redirect_location: str,
        scopes: List[TargetScope],
        project: Optional[Project] = None,
    ) -> ScopeCheckResult:
        """Validates HTTP 3xx redirect destinations to prevent out-of-scope test escapes."""
        if not redirect_location or not redirect_location.strip():
            return ScopeCheckResult(
                is_allowed=False,
                reason="Empty or missing redirect location header; failed closed.",
            )

        loc = redirect_location.strip()
        # Relative URLs stay within the current origin
        if loc.startswith("/") and not loc.startswith("//"):
            return ScopeCheckResult(
                is_allowed=True,
                reason=f"Relative redirect destination '{loc}' remains on authorized host.",
            )

        # Resolve scheme-relative or absolute URL
        if loc.startswith("//"):
            loc = "https:" + loc
        elif "://" not in loc:
            # Path-relative segment (e.g. login.php?next=/)
            return ScopeCheckResult(
                is_allowed=True,
                reason=f"Path-relative redirect '{loc}' remains on authorized host.",
            )

        try:
            parsed = urlparse(loc)
            host = parsed.hostname or ""
        except Exception:
            return ScopeCheckResult(
                is_allowed=False,
                reason=f"Malformed redirect URL '{loc}'; failed closed.",
            )

        if not host:
            return ScopeCheckResult(
                is_allowed=False,
                reason=f"Could not extract hostname from redirect '{loc}'; failed closed.",
            )

        return cls.is_target_authorized(host, scopes, project=project)

    @classmethod
    def get_scope_summary(cls, scopes: List[TargetScope]) -> Dict[str, List[str]]:
        """Returns clean categorized lists of allowed and excluded scope boundaries."""
        allowed = []
        excluded = []
        for s in scopes:
            target = s.target.strip()
            if not target:
                continue
            if s.rule_type == ScopeRuleType.EXCLUDED or not s.is_authorized:
                excluded.append(target)
            else:
                allowed.append(target)
        return {"allowed": allowed, "excluded": excluded}

    @classmethod
    def verify_scan_intent(
        cls,
        target: str,
        scopes: List[TargetScope],
        project: Optional[Project] = None,
        is_destructive: bool = False,
        source: str = "scanner",
    ) -> Tuple[bool, str]:
        """Strict pre-scan validation enforcing authorized scope and non-destructive defaults.

        Guarantees:
        - Network map nodes and unverified UI elements never confer authorization.
        - Out-of-scope or explicitly excluded targets are blocked (fail closed).
        - Destructive or intrusive actions require active authorization.
        - Rules of Engagement prohibited tests are strictly rejected.
        """
        if not target or not target.strip():
            return False, "Target specification is empty or undefined; failed closed."

        if source == "network_map":
            return False, "Network map visualization nodes do NOT confer authorization. Target must be explicitly authorized in project scope."

        # Fail closed on project lifecycle
        if project:
            if project.status == ProjectStatus.ARCHIVED:
                return False, f"Project '{project.name}' is archived; testing strictly prohibited."
            if project.status == ProjectStatus.SUSPENDED:
                return False, f"Project '{project.name}' is suspended; testing strictly prohibited."
            if project.status == ProjectStatus.PAUSED:
                return False, f"Project '{project.name}' is paused; testing temporarily suspended."
            if project.status == ProjectStatus.COMPLETED:
                return False, f"Project '{project.name}' has concluded; scope authorization closed."
            if project.status != ProjectStatus.ACTIVE:
                return False, f"Project '{project.name}' is in '{project.status.value}' state; active engagement authorization required."

        # Verify target authorization against authorized scope rules
        result = cls.is_target_authorized(target, scopes, project=project)
        if not result.is_allowed:
            return False, f"Scope authorization blocked: {result.reason}"

        # Non-destructive discovery defaults and prohibited test checks
        if is_destructive:
            if project:
                prohibited = (project.prohibited_tests or "").lower()
                if "dos" in prohibited or "destructive" in prohibited:
                    return False, "Action blocked: Destructive tests are strictly prohibited by engagement Rules of Engagement."
                if not project.allow_active_recon:
                    return False, "Action blocked: Active/intrusive testing is disabled in project settings."

        return True, f"Target '{target}' is verified and within authorized scope."
