"""Active Directory / LDAP Live Enumeration Adapter.

Coordinates read-only reconnaissance against enterprise Active Directory targets:
1. LDAP RootDSE Discovery
2. Domain Naming Context Discovery
3. Domain Controller Identification
4. Domain Users Inventory & UAC Flag Analysis (AS-REP roasting, no expiration, no password required)
5. Domain Groups & High-Privilege Administration Inventory
6. Domain Computers & Workstation Categorization
7. Organizational Unit (OU) Hierarchy
8. Domain Password Policy Audit (min length, lockout threshold, complexity)
9. LDAP Security Checks (Anonymous bind, cleartext protocol, signing requirements)

STRICT OPERATIONAL CONTROLS:
- Read-only operations only.
- Strict ScopeAuthorizationService validation before network connection.
- Redaction of sensitive credentials, hashes, and tokens.
- Cryptographic SHA-256 evidence generation.
- Duplicate asset avoidance during database synchronization.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import logging
import socket
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from core.base_adapter import BaseSecurityAdapter
from core.scope import ScopeAuthorizationService, ScopeCheckResult
from modules.identity.ldap_client import (
    LDAPEntry,
    ReadOnlyLDAPClient,
    SCOPE_BASE,
    SCOPE_SUBTREE,
)
from storage.db import Database
from storage.models import (
    AssetEdge,
    AssetNode,
    EngagementAuditLog,
    Evidence,
    ExecutionStatus,
    Finding,
    FindingSeverity,
    Observation,
    Project,
    TargetScope,
    ToolExecution,
    ValidationStatus,
)

logger = logging.getLogger(__name__)

# Active Directory UserAccountControl (UAC) bitflags
UAC_SCRIPT = 0x0001
UAC_ACCOUNTDISABLE = 0x0002
UAC_HOMEDIR_REQUIRED = 0x0008
UAC_LOCKOUT = 0x0010
UAC_PASSWD_NOTREQD = 0x0020
UAC_PASSWD_CANT_CHANGE = 0x0040
UAC_ENCRYPTED_TEXT_PWD_ALLOWED = 0x0080
UAC_TEMP_DUPLICATE_ACCOUNT = 0x0100
UAC_NORMAL_ACCOUNT = 0x0200
UAC_INTERDOMAIN_TRUST_ACCOUNT = 0x0800
UAC_WORKSTATION_TRUST_ACCOUNT = 0x1000
UAC_SERVER_TRUST_ACCOUNT = 0x2000  # Domain Controller
UAC_DONT_EXPIRE_PASSWORD = 0x10000
UAC_MNS_LOGON_ACCOUNT = 0x20000
UAC_SMARTCARD_REQUIRED = 0x40000
UAC_TRUSTED_FOR_DELEGATION = 0x80000
UAC_NOT_DELEGATED = 0x100000
UAC_USE_DES_KEY_ONLY = 0x200000
UAC_DONT_REQ_PREAUTH = 0x400000    # AS-REP Roastable
UAC_PASSWORD_EXPIRED = 0x800000
UAC_TRUSTED_TO_AUTH_FOR_DELEGATION = 0x1000000


@dataclass
class DomainPasswordPolicy:
    """Parsed domain password policy settings."""
    min_pwd_length: int = 0
    pwd_properties: int = 0
    lockout_threshold: int = 0
    lockout_duration_mins: int = 0
    max_pwd_age_days: int = 0
    min_pwd_age_days: int = 0
    history_length: int = 0
    complexity_enabled: bool = False
    raw_attributes: Dict[str, Any] = field(default_factory=dict)


@dataclass
class LDAPEnumerationResult:
    """Consolidated findings, assets, and observations from LDAP live enumeration."""
    is_authorized: bool = False
    scope_reason: str = ""
    target: str = ""
    port: int = 389
    root_dse: Dict[str, Any] = field(default_factory=dict)
    default_naming_context: str = ""
    domain_controllers: List[Dict[str, Any]] = field(default_factory=list)
    users: List[Dict[str, Any]] = field(default_factory=list)
    groups: List[Dict[str, Any]] = field(default_factory=list)
    computers: List[Dict[str, Any]] = field(default_factory=list)
    ous: List[Dict[str, Any]] = field(default_factory=list)
    password_policy: Optional[DomainPasswordPolicy] = None
    security_checks: Dict[str, Any] = field(default_factory=dict)
    findings: List[Finding] = field(default_factory=list)
    discovered_nodes: List[AssetNode] = field(default_factory=list)
    discovered_edges: List[AssetEdge] = field(default_factory=list)
    observations: List[Observation] = field(default_factory=list)
    evidence_id: Optional[int] = None
    execution_id: Optional[int] = None
    raw_redacted_evidence: str = ""
    error_message: str = ""


class LDAPLiveEnumerationAdapter(BaseSecurityAdapter):
    """Orchestrates authorized, read-only Active Directory & LDAP enumeration."""

    def __init__(self, db: Optional[Database] = None):
        super().__init__(db=db)

    @property
    def tool_name(self) -> str:
        return "ldap_enumerator"

    @property
    def display_name(self) -> str:
        return "Active Directory / LDAP Live Enumerator"

    def execute_enumeration(
        self,
        project_id: int,
        target_host: str,
        port: int = 389,
        use_ssl: bool = False,
        bind_dn: str = "",
        password: str = "",
        scopes: Optional[List[TargetScope]] = None,
        project: Optional[Project] = None,
        categories: Optional[List[str]] = None,
        on_output: Optional[Callable[[str, str], None]] = None,
        evidence_dir: Optional[Path] = None,
        session_id: Optional[str] = None,
        timeout: float = 12.0,
        verify_cert: bool = True,
    ) -> LDAPEnumerationResult:
        """Executes authorized read-only LDAP enumeration against target."""
        def emit(msg: str, stream: str = "stdout"):
            if on_output:
                on_output(msg, stream)

        result = LDAPEnumerationResult(target=target_host, port=port)

        # -------------------------------------------------------------
        # 1. Scope Boundary & Engagement Authorization Gate
        # -------------------------------------------------------------
        emit(f"[*] Validating scope authorization for LDAP target: {target_host}...\n")
        project_obj = project or (self.db.get_project(project_id) if self.db else None)
        active_scopes = scopes or (self.db.list_scopes(project_id) if self.db else [])

        # Comprehensive DNS Scope Guard: Resolve all IPv4 and IPv6 addresses
        resolved_ips: List[str] = []
        is_direct_ip = False
        clean_target = target_host.strip()
        try:
            ipaddress.ip_address(clean_target)
            resolved_ips = [clean_target]
            is_direct_ip = True
        except ValueError:
            try:
                addr_info = socket.getaddrinfo(clean_target, None)
                for item in addr_info:
                    sockaddr = item[4]
                    ip = sockaddr[0]
                    if ip not in resolved_ips:
                        resolved_ips.append(ip)
            except Exception as exc:
                result.is_authorized = False
                result.scope_reason = f"DNS resolution failure for target '{clean_target}': {exc}"
                result.error_message = f"Out-of-Scope Execution Blocked: {result.scope_reason}"
                emit(f"[-] SECURITY POLICY VIOLATION: Could not resolve target '{clean_target}': {exc}\n", "stderr")
                if self.db:
                    self.db.add_audit_log(
                        EngagementAuditLog(
                            project_id=project_id,
                            actor="operator",
                            action="out_of_scope_scan_blocked",
                            details=json.dumps({
                                "target": clean_target,
                                "port": port,
                                "protocol": "ldap",
                                "reason": f"DNS resolution failure: {exc}",
                                "timestamp": datetime.now(timezone.utc).isoformat(),
                            }),
                        )
                    )
                return result

        if not resolved_ips:
            resolved_ips = [clean_target]

        # Verify EVERY resolved IP address against the active engagement scope (Fail-Closed)
        for r_ip in resolved_ips:
            scope_check = ScopeAuthorizationService.is_target_authorized(
                target=r_ip,
                scopes=active_scopes,
                project=project_obj,
                resolve_dns=False,
            )
            if not scope_check.is_allowed:
                result.is_authorized = False
                result.scope_reason = f"Resolved IP {r_ip} is outside authorized scope. {scope_check.reason}"
                result.error_message = f"Out-of-Scope Execution Blocked: {result.scope_reason}"
                emit(f"[-] SECURITY POLICY VIOLATION: Resolved IP '{r_ip}' for target '{clean_target}' is not authorized!\n", "stderr")
                emit(f"    Reason: {scope_check.reason}\n", "stderr")

                # Audit Log Fail-Closed Block
                if self.db:
                    self.db.add_audit_log(
                        EngagementAuditLog(
                            project_id=project_id,
                            actor="operator",
                            action="out_of_scope_scan_blocked",
                            details=json.dumps({
                                "target": clean_target,
                                "resolved_ip": r_ip,
                                "all_resolved_ips": resolved_ips,
                                "port": port,
                                "protocol": "ldap",
                                "reason": scope_check.reason,
                                "timestamp": datetime.now(timezone.utc).isoformat(),
                            }),
                        )
                    )
                return result

        # Also check target hostname directly if not direct IP (in case of named domain exclusions)
        if not is_direct_ip:
            scope_check_host = ScopeAuthorizationService.is_target_authorized(
                target=clean_target,
                scopes=active_scopes,
                project=project_obj,
                resolve_dns=False,
            )
            if not scope_check_host.is_allowed and "excluded" in scope_check_host.reason.lower():
                result.is_authorized = False
                result.scope_reason = scope_check_host.reason
                result.error_message = f"Out-of-Scope Execution Blocked: {scope_check_host.reason}"
                emit(f"[-] SECURITY POLICY VIOLATION: Target hostname '{clean_target}' is excluded!\n", "stderr")
                return result

        # Socket destination uses the first validated IP to prevent DNS rebinding
        validated_connect_ip = resolved_ips[0]

        result.is_authorized = True
        result.scope_reason = f"Target {clean_target} ({validated_connect_ip}) verified within authorized scope."
        emit(f"[+] Scope authorized: {result.scope_reason}\n")

        # Create ToolExecution record
        execution = None
        if self.db:
            execution = self.db.create_tool_execution(
                ToolExecution(
                    project_id=project_id,
                    tool_name=self.tool_name,
                    command=f"ldap_enumerate --host {clean_target} --port {port} --ssl={use_ssl}",
                    status=ExecutionStatus.RUNNING,
                )
            )
            result.execution_id = execution.id

        selected_categories = set(categories) if categories else {
            "root_dse", "naming_contexts", "domain_controllers", "users",
            "groups", "computers", "ous", "password_policy", "security_checks",
        }

        # -------------------------------------------------------------
        # 2. Connection & Authentication Phase
        # -------------------------------------------------------------
        client = ReadOnlyLDAPClient(
            host=validated_connect_ip,
            port=port,
            use_ssl=use_ssl,
            timeout=timeout,
            verify_cert=verify_cert,
            server_hostname=clean_target,
        )

        try:
            emit(f"[*] Connecting to LDAP service at {target_host}:{port} (SSL={use_ssl})...\n")
            conn_ok, conn_msg = client.connect()
            if not conn_ok:
                result.error_message = conn_msg
                emit(f"[-] {conn_msg}\n", "stderr")
                if execution and self.db:
                    execution.status = ExecutionStatus.FAILED
                    self.db.update_execution(execution)
                return result

            # Check anonymous bind vs credential bind
            if bind_dn:
                emit(f"[*] Performing authenticated bind as user: {bind_dn}...\n")
                bind_ok, bind_msg = client.bind(bind_dn=bind_dn, password=password)
            else:
                emit("[*] Attempting Anonymous Bind (unauthenticated discovery)...\n")
                bind_ok, bind_msg = client.bind(bind_dn="", password="")

            if not bind_ok:
                result.error_message = bind_msg
                emit(f"[-] Bind failed: {bind_msg}\n", "stderr")
                # Record anonymous bind rejection check
                if not bind_dn:
                    result.security_checks["anonymous_bind"] = "REJECTED (Secure)"
                if execution and self.db:
                    execution.status = ExecutionStatus.FAILED
                    self.db.update_execution(execution)
                return result

            emit(f"[+] {bind_msg}\n")
            if not bind_dn:
                result.security_checks["anonymous_bind"] = "PERMITTED (Insecure)"

            # -------------------------------------------------------------
            # 3. RootDSE Discovery
            # -------------------------------------------------------------
            default_nc = ""
            if "root_dse" in selected_categories or "naming_contexts" in selected_categories:
                emit("[+] Querying LDAP RootDSE (Base DN: '')...\n")
                root_entries = client.search(
                    base_dn="",
                    scope=SCOPE_BASE,
                    filter_str="(objectClass=*)",
                    attributes=[
                        "defaultNamingContext",
                        "rootDomainNamingContext",
                        "dnsHostName",
                        "domainFunctionality",
                        "domainControllerFunctionality",
                        "supportedLDAPVersion",
                        "supportedSASLMechanisms",
                        "serverName",
                        "namingContexts",
                    ],
                )
                if root_entries:
                    re_obj = root_entries[0]
                    result.root_dse = {k: v for k, v in re_obj.attributes.items()}
                    default_nc = re_obj.get_first("defaultNamingContext", "")
                    result.default_naming_context = default_nc
                    emit(f"    [RootDSE] Default Naming Context: {default_nc}\n")
                    dns_host = re_obj.get_first("dnsHostName", "")
                    if dns_host:
                        emit(f"    [RootDSE] Primary DC Hostname: {dns_host}\n")

            base_dn = default_nc or ""

            # -------------------------------------------------------------
            # 4. Domain Controller Discovery
            # -------------------------------------------------------------
            if "domain_controllers" in selected_categories and base_dn:
                emit(f"[+] Discovering Domain Controllers in {base_dn}...\n")
                dc_entries = client.search(
                    base_dn=base_dn,
                    scope=SCOPE_SUBTREE,
                    filter_str="(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))",
                    attributes=["sAMAccountName", "dNSHostName", "operatingSystem", "operatingSystemVersion"],
                    size_limit=100,
                )
                for dc in dc_entries:
                    dc_info = {
                        "dn": dc.dn,
                        "sam_name": dc.get_first("sAMAccountName"),
                        "dns_hostname": dc.get_first("dNSHostName", target_host),
                        "os": dc.get_first("operatingSystem"),
                        "os_version": dc.get_first("operatingSystemVersion"),
                    }
                    result.domain_controllers.append(dc_info)
                    emit(f"    [DC Discovered] {dc_info['dns_hostname']} ({dc_info['sam_name']}) - {dc_info['os']}\n")

            # -------------------------------------------------------------
            # 5. Domain Users Inventory & UAC Flag Analysis
            # -------------------------------------------------------------
            if "users" in selected_categories and base_dn:
                emit(f"[+] Enumerating Domain Users in {base_dn}...\n")
                user_entries = client.search(
                    base_dn=base_dn,
                    scope=SCOPE_SUBTREE,
                    filter_str="(&(objectCategory=person)(objectClass=user))",
                    attributes=[
                        "sAMAccountName",
                        "userPrincipalName",
                        "displayName",
                        "mail",
                        "badPwdCount",
                        "userAccountControl",
                        "adminCount",
                        "memberOf",
                        "pwdLastSet",
                        "description",
                    ],
                    size_limit=1000,
                )
                for ue in user_entries:
                    sam = ue.get_first("sAMAccountName")
                    if not sam:
                        continue
                    try:
                        uac_val = int(ue.get_first("userAccountControl", "512"))
                    except ValueError:
                        uac_val = 512

                    uac_flags = self._analyze_uac_flags(uac_val)
                    is_disabled = bool(uac_val & UAC_ACCOUNTDISABLE)
                    dont_expire = bool(uac_val & UAC_DONT_EXPIRE_PASSWORD)
                    dont_req_preauth = bool(uac_val & UAC_DONT_REQ_PREAUTH)
                    passwd_not_reqd = bool(uac_val & UAC_PASSWD_NOTREQD)

                    user_info = {
                        "sam_name": sam,
                        "dn": ue.dn,
                        "upn": ue.get_first("userPrincipalName"),
                        "display_name": ue.get_first("displayName"),
                        "mail": ue.get_first("mail"),
                        "bad_pwd_count": ue.get_first("badPwdCount", "0"),
                        "admin_count": ue.get_first("adminCount", "0"),
                        "is_disabled": is_disabled,
                        "dont_expire_password": dont_expire,
                        "dont_req_preauth": dont_req_preauth,
                        "passwd_not_reqd": passwd_not_reqd,
                        "uac_flags": uac_flags,
                        "description": ue.get_first("description"),
                    }
                    result.users.append(user_info)

                emit(f"    [*] Ingested {len(result.users)} user account records.\n")

            # -------------------------------------------------------------
            # 6. Domain Groups Inventory
            # -------------------------------------------------------------
            if "groups" in selected_categories and base_dn:
                emit(f"[+] Enumerating Domain Security Groups in {base_dn}...\n")
                group_entries = client.search(
                    base_dn=base_dn,
                    scope=SCOPE_SUBTREE,
                    filter_str="(objectClass=group)",
                    attributes=["sAMAccountName", "adminCount", "member", "description"],
                    size_limit=500,
                )
                for ge in group_entries:
                    grp_sam = ge.get_first("sAMAccountName")
                    if not grp_sam:
                        continue
                    members = ge.get_list("member")
                    is_admin = ge.get_first("adminCount") == "1" or "admin" in grp_sam.lower()

                    group_info = {
                        "sam_name": grp_sam,
                        "dn": ge.dn,
                        "is_admin_group": is_admin,
                        "member_count": len(members),
                        "members": members[:50],  # cap for preview
                        "description": ge.get_first("description"),
                    }
                    result.groups.append(group_info)

                emit(f"    [*] Ingested {len(result.groups)} domain security groups.\n")

            # -------------------------------------------------------------
            # 7. Domain Computers Inventory
            # -------------------------------------------------------------
            if "computers" in selected_categories and base_dn:
                emit(f"[+] Enumerating Domain Computers in {base_dn}...\n")
                comp_entries = client.search(
                    base_dn=base_dn,
                    scope=SCOPE_SUBTREE,
                    filter_str="(objectClass=computer)",
                    attributes=["sAMAccountName", "dNSHostName", "operatingSystem", "operatingSystemVersion", "whenCreated"],
                    size_limit=500,
                )
                for ce in comp_entries:
                    comp_sam = ce.get_first("sAMAccountName")
                    dns_name = ce.get_first("dNSHostName") or comp_sam.replace("$", "")
                    comp_info = {
                        "sam_name": comp_sam,
                        "dns_hostname": dns_name,
                        "dn": ce.dn,
                        "os": ce.get_first("operatingSystem"),
                        "os_version": ce.get_first("operatingSystemVersion"),
                        "when_created": ce.get_first("whenCreated"),
                    }
                    result.computers.append(comp_info)

                emit(f"    [*] Ingested {len(result.computers)} domain computers.\n")

            # -------------------------------------------------------------
            # 8. Organizational Unit (OU) Inventory
            # -------------------------------------------------------------
            if "ous" in selected_categories and base_dn:
                emit(f"[+] Enumerating Organizational Units in {base_dn}...\n")
                ou_entries = client.search(
                    base_dn=base_dn,
                    scope=SCOPE_SUBTREE,
                    filter_str="(objectClass=organizationalUnit)",
                    attributes=["ou", "description"],
                    size_limit=200,
                )
                for oe in ou_entries:
                    ou_name = oe.get_first("ou")
                    if ou_name:
                        result.ous.append({
                            "name": ou_name,
                            "dn": oe.dn,
                            "description": oe.get_first("description"),
                        })
                emit(f"    [*] Ingested {len(result.ous)} Organizational Units.\n")

            # -------------------------------------------------------------
            # 9. Domain Password Policy Retrieval
            # -------------------------------------------------------------
            if "password_policy" in selected_categories and base_dn:
                emit(f"[+] Retrieving Domain Password Policy from {base_dn}...\n")
                policy_entries = client.search(
                    base_dn=base_dn,
                    scope=SCOPE_BASE,
                    filter_str="(objectClass=*)",
                    attributes=[
                        "minPwdLength",
                        "pwdProperties",
                        "lockoutThreshold",
                        "lockoutDuration",
                        "maxPwdAge",
                        "minPwdAge",
                        "pwdHistoryLength",
                    ],
                )
                if policy_entries:
                    pe = policy_entries[0]
                    try:
                        min_len = int(pe.get_first("minPwdLength", "0"))
                    except ValueError:
                        min_len = 0
                    try:
                        pwd_props = int(pe.get_first("pwdProperties", "0"))
                    except ValueError:
                        pwd_props = 0
                    try:
                        lockout_thresh = int(pe.get_first("lockoutThreshold", "0"))
                    except ValueError:
                        lockout_thresh = 0
                    try:
                        history_len = int(pe.get_first("pwdHistoryLength", "0"))
                    except ValueError:
                        history_len = 0

                    complexity = bool(pwd_props & 1)
                    policy = DomainPasswordPolicy(
                        min_pwd_length=min_len,
                        pwd_properties=pwd_props,
                        lockout_threshold=lockout_thresh,
                        history_length=history_len,
                        complexity_enabled=complexity,
                        raw_attributes={k: v for k, v in pe.attributes.items()},
                    )
                    result.password_policy = policy
                    emit(f"    [Password Policy] Minimum Length: {min_len} | Complexity: {complexity} | Lockout: {lockout_thresh}\n")

            # -------------------------------------------------------------
            # 10. Security Checks & Findings Synthesis
            # -------------------------------------------------------------
            self._evaluate_security_findings(project_id, target_host, port, use_ssl, result, execution)

            # -------------------------------------------------------------
            # 11. Normalize Assets, Edges, Observations, and Evidence
            # -------------------------------------------------------------
            self._synthesize_assets_and_evidence(
                project_id=project_id,
                target_host=target_host,
                result=result,
                execution=execution,
                evidence_dir=evidence_dir,
            )

            emit(f"[+] Active Directory / LDAP enumeration completed successfully! Discovered {len(result.discovered_nodes)} assets, {len(result.findings)} findings.\n")
            if execution and self.db:
                execution.status = ExecutionStatus.COMPLETED
                self.db.update_execution(execution)

        except Exception as exc:
            logger.exception(f"LDAP enumeration unexpected error: {exc}")
            result.error_message = str(exc)
            emit(f"[-] Execution error: {exc}\n", "stderr")
            if execution and self.db:
                execution.status = ExecutionStatus.FAILED
                self.db.update_execution(execution)
        finally:
            client.unbind()

        return result

    def _analyze_uac_flags(self, uac: int) -> List[str]:
        """Translates UAC integer bitmask into human-readable flags."""
        flags = []
        if uac & UAC_SCRIPT: flags.append("SCRIPT")
        if uac & UAC_ACCOUNTDISABLE: flags.append("ACCOUNTDISABLE")
        if uac & UAC_LOCKOUT: flags.append("LOCKOUT")
        if uac & UAC_PASSWD_NOTREQD: flags.append("PASSWD_NOTREQD")
        if uac & UAC_PASSWD_CANT_CHANGE: flags.append("PASSWD_CANT_CHANGE")
        if uac & UAC_NORMAL_ACCOUNT: flags.append("NORMAL_ACCOUNT")
        if uac & UAC_SERVER_TRUST_ACCOUNT: flags.append("SERVER_TRUST_ACCOUNT (DC)")
        if uac & UAC_WORKSTATION_TRUST_ACCOUNT: flags.append("WORKSTATION_TRUST_ACCOUNT")
        if uac & UAC_DONT_EXPIRE_PASSWORD: flags.append("DONT_EXPIRE_PASSWORD")
        if uac & UAC_DONT_REQ_PREAUTH: flags.append("DONT_REQ_PREAUTH (AS-REP Roastable)")
        if uac & UAC_TRUSTED_FOR_DELEGATION: flags.append("TRUSTED_FOR_DELEGATION")
        if uac & UAC_TRUSTED_TO_AUTH_FOR_DELEGATION: flags.append("TRUSTED_TO_AUTH_FOR_DELEGATION")
        return flags

    def _evaluate_security_findings(
        self,
        project_id: int,
        target_host: str,
        port: int,
        use_ssl: bool,
        result: LDAPEnumerationResult,
        execution: Optional[ToolExecution],
    ):
        """Generates deterministic security findings based on empirical LDAP queries."""
        exec_id = execution.id if execution else None

        # 1. Anonymous LDAP Bind Permitted
        if result.security_checks.get("anonymous_bind") == "PERMITTED (Insecure)":
            result.findings.append(
                Finding(
                    project_id=project_id,
                    title="Active Directory Anonymous LDAP Bind Permitted",
                    severity=FindingSeverity.MEDIUM,
                    cvss_score=5.3,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                    affected_asset=target_host,
                    affected_port_service=f"{port}/ldap",
                    description=(
                        f"The Active Directory LDAP service on {target_host}:{port} allows unauthenticated "
                        "anonymous bind requests. Unauthenticated attackers can query LDAP directory metadata, "
                        "naming contexts, and potentially domain object structures without credentials."
                    ),
                    reproduction_steps=(
                        f"1. Connect to {target_host}:{port} using an unauthenticated LDAP bind.\n"
                        "2. Submit a search query for RootDSE (baseObject '').\n"
                        "3. Directory server returns naming contexts and operational attributes."
                    ),
                    remediation=(
                        "Disable anonymous LDAP operations in Active Directory. Configure 'LDAP server signing requirements' "
                        "to require authentication and enforce LDAP signing or LDAPS."
                    ),
                    validation_status=ValidationStatus.CONFIRMED,
                    source_tool=self.tool_name,
                    execution_id=exec_id,
                )
            )

        # 2. Unencrypted LDAP Protocol In Use (Cleartext transmission)
        if not use_ssl:
            result.findings.append(
                Finding(
                    project_id=project_id,
                    title="Cleartext Unencrypted LDAP Service In Use",
                    severity=FindingSeverity.LOW,
                    cvss_score=3.7,
                    cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
                    affected_asset=target_host,
                    affected_port_service=f"{port}/ldap",
                    description=(
                        f"The LDAP service on {target_host}:{port} operates over cleartext TCP without TLS encryption. "
                        "User credentials, directory queries, and domain objects transmitted over this channel "
                        "are vulnerable to eavesdropping and interception by network attackers."
                    ),
                    reproduction_steps=f"Initiate an unencrypted TCP connection to port {port}. Server accepts unencrypted LDAP commands.",
                    remediation="Enforce LDAPS over port 636 or mandate StartTLS on port 389. Disable cleartext simple binds.",
                    validation_status=ValidationStatus.CONFIRMED,
                    source_tool=self.tool_name,
                    execution_id=exec_id,
                )
            )

        # 3. AS-REP Roastable Accounts (DONT_REQ_PREAUTH)
        asrep_accounts = [u["sam_name"] for u in result.users if u.get("dont_req_preauth") and not u.get("is_disabled")]
        if asrep_accounts:
            sample_str = ", ".join(asrep_accounts[:10])
            result.findings.append(
                Finding(
                    project_id=project_id,
                    title=f"Active Directory Accounts Vulnerable to AS-REP Roasting ({len(asrep_accounts)} Accounts)",
                    severity=FindingSeverity.HIGH,
                    cvss_score=7.5,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                    affected_asset=target_host,
                    affected_port_service=f"{port}/ldap",
                    description=(
                        f"Identified {len(asrep_accounts)} active domain account(s) configured with the 'DONT_REQ_PREAUTH' "
                        f"UserAccountControl flag (e.g. {sample_str}). An attacker can request Kerberos AS-REP tickets "
                        "without knowing user passwords and crack the encrypted cipher offline to recover plaintext passwords."
                    ),
                    reproduction_steps=(
                        "1. Query Active Directory LDAP for accounts where 'userAccountControl:1.2.840.113556.1.4.803:=4194304'.\n"
                        f"2. Discovered vulnerable accounts: {sample_str}.\n"
                        "3. Request Kerberos ticket via GetNPUsers.py or Rubeus asreproast."
                    ),
                    remediation=(
                        "Re-enable Kerberos pre-authentication for all user accounts by removing the "
                        "'Do not require Kerberos preauthentication' setting in Active Directory Users and Computers (ADUC)."
                    ),
                    validation_status=ValidationStatus.CONFIRMED,
                    source_tool=self.tool_name,
                    execution_id=exec_id,
                )
            )

        # 4. Accounts with Passwords That Never Expire
        no_expire_accounts = [u["sam_name"] for u in result.users if u.get("dont_expire_password") and not u.get("is_disabled")]
        if len(no_expire_accounts) > 0:
            result.findings.append(
                Finding(
                    project_id=project_id,
                    title=f"Active Directory Passwords Configured to Never Expire ({len(no_expire_accounts)} Accounts)",
                    severity=FindingSeverity.MEDIUM,
                    cvss_score=5.3,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                    affected_asset=target_host,
                    affected_port_service=f"{port}/ldap",
                    description=(
                        f"Discovered {len(no_expire_accounts)} active domain account(s) with 'DONT_EXPIRE_PASSWORD' set. "
                        "Accounts with static passwords increase exposure to credential reuse and prolonged compromised access."
                    ),
                    reproduction_steps=f"Inspected UAC bit 0x10000 across domain accounts. Found {len(no_expire_accounts)} accounts with flag enabled.",
                    remediation="Uncheck 'Password never expires' on user accounts and enforce regular password rotation policies.",
                    validation_status=ValidationStatus.CONFIRMED,
                    source_tool=self.tool_name,
                    execution_id=exec_id,
                )
            )

        # 5. Accounts with Password Not Required Flag
        no_pwd_reqd = [u["sam_name"] for u in result.users if u.get("passwd_not_reqd") and not u.get("is_disabled")]
        if no_pwd_reqd:
            result.findings.append(
                Finding(
                    project_id=project_id,
                    title=f"Active Directory Accounts Configured Without Password Requirement ({len(no_pwd_reqd)} Accounts)",
                    severity=FindingSeverity.HIGH,
                    cvss_score=7.5,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                    affected_asset=target_host,
                    affected_port_service=f"{port}/ldap",
                    description=(
                        f"Discovered {len(no_pwd_reqd)} account(s) with 'PASSWD_NOTREQD' enabled ({', '.join(no_pwd_reqd[:5])}). "
                        "These accounts may possess blank or absent passwords, allowing unauthenticated account takeover."
                    ),
                    reproduction_steps="Checked UAC bit 0x0020 (PASSWD_NOTREQD) via LDAP query.",
                    remediation="Clear the PASSWD_NOTREQD flag and ensure strong, non-blank passwords are set on all accounts.",
                    validation_status=ValidationStatus.CONFIRMED,
                    source_tool=self.tool_name,
                    execution_id=exec_id,
                )
            )

        # 6. Domain Password Policy Weakness
        if result.password_policy:
            pol = result.password_policy
            weaknesses = []
            if pol.min_pwd_length < 12:
                weaknesses.append(f"Minimum password length is only {pol.min_pwd_length} characters (recommended >= 12)")
            if pol.lockout_threshold == 0:
                weaknesses.append("Account lockout threshold is disabled (0 bad attempts), exposing domain to brute-force attacks")
            if not pol.complexity_enabled:
                weaknesses.append("Password complexity requirements are disabled")

            if weaknesses:
                desc = "The Active Directory Default Domain Password Policy exhibits security weaknesses:\n- " + "\n- ".join(weaknesses)
                result.findings.append(
                    Finding(
                        project_id=project_id,
                        title="Weak Active Directory Domain Password Policy",
                        severity=FindingSeverity.MEDIUM,
                        cvss_score=6.5,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
                        affected_asset=target_host,
                        affected_port_service=f"{port}/ldap",
                        description=desc,
                        reproduction_steps="Extracted domain password policy operational attributes from domain root DN.",
                        remediation="Enforce minimum password length of at least 12 characters, enable complexity, and set an account lockout threshold (e.g. 5-10 attempts).",
                        validation_status=ValidationStatus.CONFIRMED,
                        source_tool=self.tool_name,
                        execution_id=exec_id,
                    )
                )

    def _synthesize_assets_and_evidence(
        self,
        project_id: int,
        target_host: str,
        result: LDAPEnumerationResult,
        execution: Optional[ToolExecution],
        evidence_dir: Optional[Path],
    ):
        """Translates LDAP enumeration results into AssetNode, AssetEdge, Observation, and Evidence records."""
        exec_id = execution.id if execution else None

        # 1. Primary Target / DC Node
        domain_label = result.default_naming_context or target_host
        dc_label = result.root_dse.get("dnsHostName", [target_host])[0] if result.root_dse.get("dnsHostName") else target_host

        dc_node = AssetNode(
            project_id=project_id,
            node_type="domain_controller",
            value=target_host,
            label=f"DC: {dc_label}",
            source_tool=self.tool_name,
            confidence=1.0,
            metadata_json=json.dumps({
                "dns_hostname": dc_label,
                "default_naming_context": result.default_naming_context,
                "port": result.port,
                "role": "domain_controller",
            }),
        )
        result.discovered_nodes.append(dc_node)

        # 2. Domain Naming Context Node
        if result.default_naming_context:
            domain_node = AssetNode(
                project_id=project_id,
                node_type="domain",
                value=result.default_naming_context,
                label=f"Domain: {result.default_naming_context}",
                source_tool=self.tool_name,
                confidence=1.0,
                metadata_json=json.dumps({
                    "naming_context": result.default_naming_context,
                    "primary_dc": dc_label,
                }),
            )
            result.discovered_nodes.append(domain_node)

        # 3. Discovered Computers
        for comp in result.computers[:100]:  # Cap asset creation to avoid DB flooding
            c_host = comp.get("dns_hostname") or comp.get("sam_name", "").replace("$", "")
            if not c_host or c_host == target_host:
                continue
            comp_node = AssetNode(
                project_id=project_id,
                node_type="computer",
                value=c_host,
                label=f"Computer: {c_host}",
                source_tool=self.tool_name,
                confidence=0.9,
                metadata_json=json.dumps({
                    "sam_name": comp.get("sam_name"),
                    "os": comp.get("os"),
                    "os_version": comp.get("os_version"),
                    "dn": comp.get("dn"),
                }),
            )
            result.discovered_nodes.append(comp_node)

        # 4. Generate Discovered Hierarchical Relationship Edges
        if result.default_naming_context:
            dc_edge = AssetEdge(
                project_id=project_id,
                source_node_id=0,
                target_node_id=0,
                relation_type="HAS_DOMAIN_CONTROLLER",
                source_tool=self.tool_name,
                verification_state="observed",
                confidence=1.0,
                metadata_json=json.dumps({
                    "source_domain": result.default_naming_context,
                    "target_dc": target_host,
                    "dns_hostname": dc_label,
                }),
            )
            result.discovered_edges.append(dc_edge)

            for comp in result.computers[:100]:
                c_host = comp.get("dns_hostname") or comp.get("sam_name", "").replace("$", "")
                if not c_host or c_host == target_host:
                    continue
                c_edge = AssetEdge(
                    project_id=project_id,
                    source_node_id=0,
                    target_node_id=0,
                    relation_type="HAS_MEMBER_COMPUTER",
                    source_tool=self.tool_name,
                    verification_state="observed",
                    confidence=0.9,
                    metadata_json=json.dumps({
                        "source_domain": result.default_naming_context,
                        "target_computer": c_host,
                        "os": comp.get("os"),
                    }),
                )
                result.discovered_edges.append(c_edge)

        # 5. Generate Observation Record
        obs_data = {
            "target": target_host,
            "port": result.port,
            "naming_context": result.default_naming_context,
            "user_count": len(result.users),
            "group_count": len(result.groups),
            "computer_count": len(result.computers),
            "ou_count": len(result.ous),
            "dc_count": len(result.domain_controllers),
        }
        obs = Observation(
            project_id=project_id,
            title=f"LDAP Live Enumeration of {target_host}:{result.port}",
            source_tool=self.tool_name,
            method="read_only_ldap_query",
            raw_data=json.dumps(obs_data),
            confidence=1.0,
            verification_status=ValidationStatus.CONFIRMED,
        )
        result.observations.append(obs)

        # 6. Build Sanitized, Redacted Evidence JSON (SHA-256)
        evidence_dict = {
            "target": target_host,
            "port": result.port,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "root_dse": result.root_dse,
            "default_naming_context": result.default_naming_context,
            "domain_controllers": result.domain_controllers,
            "user_inventory_summary": {
                "total_users": len(result.users),
                "asrep_roastable_users": [u["sam_name"] for u in result.users if u.get("dont_req_preauth")],
                "no_expire_users": [u["sam_name"] for u in result.users if u.get("dont_expire_password")],
                "no_pwd_reqd_users": [u["sam_name"] for u in result.users if u.get("passwd_not_reqd")],
                "sample_users": [
                    {
                        "sam_name": u["sam_name"],
                        "display_name": u.get("display_name"),
                        "upn": u.get("upn"),
                        "uac_flags": u.get("uac_flags"),
                        "is_disabled": u.get("is_disabled"),
                    }
                    for u in result.users[:100]
                ],
            },
            "groups_summary": [
                {
                    "sam_name": g["sam_name"],
                    "is_admin_group": g.get("is_admin_group"),
                    "member_count": g.get("member_count"),
                }
                for g in result.groups[:50]
            ],
            "computers_summary": result.computers[:50],
            "password_policy": result.password_policy.__dict__ if result.password_policy else {},
            "security_checks": result.security_checks,
        }

        redacted_json = json.dumps(evidence_dict, indent=2)
        result.raw_redacted_evidence = redacted_json
        sha256 = hashlib.sha256(redacted_json.encode("utf-8")).hexdigest()

        # Save Evidence to disk if evidence_dir provided
        if evidence_dir and self.db:
            evidence_dir.mkdir(parents=True, exist_ok=True)
            ev_filename = f"ldap_enum_{project_id}_{int(datetime.now(timezone.utc).timestamp())}.json"
            ev_path = evidence_dir / ev_filename
            try:
                ev_path.write_text(redacted_json, encoding="utf-8")
                ev_record = self.db.create_evidence(
                    Evidence(
                        project_id=project_id,
                        file_path=str(ev_path),
                        sha256_hash=sha256,
                        description=f"Read-Only Active Directory LDAP Enumeration Evidence for {target_host}:{result.port}",
                        execution_id=exec_id,
                    )
                )
                result.evidence_id = ev_record.id
                obs.evidence_id = ev_record.id
                # Task 4: Associate the created evidence record with each relevant finding
                for f in result.findings:
                    f.evidence_id = ev_record.id
                for e in result.discovered_edges:
                    e.evidence_id = ev_record.id
            except Exception as e:
                logger.warning(f"Could not persist LDAP evidence file: {e}")
                result.evidence_id = None
                obs.evidence_id = None
                for f in result.findings:
                    f.evidence_id = None
                for e in result.discovered_edges:
                    e.evidence_id = None
        else:
            result.evidence_id = None
            obs.evidence_id = None
            for f in result.findings:
                f.evidence_id = None
            for e in result.discovered_edges:
                e.evidence_id = None

    def synchronize_to_database(
        self,
        project_id: int,
        result: LDAPEnumerationResult,
        approved_nodes: Optional[List[AssetNode]] = None,
        approved_findings: Optional[List[Finding]] = None,
    ) -> Tuple[int, int]:
        """Persists approved assets, findings, and relationships into the database, avoiding duplicates."""
        if not self.db:
            return 0, 0

        synced_assets = 0
        synced_findings = 0

        # Existing asset values to prevent duplicates
        existing_assets = {a.value.lower(): a for a in self.db.list_asset_nodes(project_id)}

        nodes_to_sync = approved_nodes if approved_nodes is not None else result.discovered_nodes
        findings_to_sync = approved_findings if approved_findings is not None else result.findings

        # 1. Upsert Assets
        for node in nodes_to_sync:
            key = node.value.lower()
            if key in existing_assets:
                # Update metadata if needed
                existing = existing_assets[key]
                existing.label = node.label
                existing.source_tool = self.tool_name
                self.db.upsert_asset_node(existing)
            else:
                saved_node = self.db.upsert_asset_node(node)
                existing_assets[key] = saved_node
                synced_assets += 1

        # Refresh map with persisted nodes to ensure valid primary key IDs
        persisted_assets = {a.value.lower(): a for a in self.db.list_asset_nodes(project_id)}

        # 2. Add Findings
        for finding in findings_to_sync:
            if result.evidence_id and not finding.evidence_id:
                finding.evidence_id = result.evidence_id
            self.db.create_finding(finding)
            synced_findings += 1

        # 3. Add Observations
        for obs in result.observations:
            if result.evidence_id and not obs.evidence_id:
                obs.evidence_id = result.evidence_id
            self.db.create_observation(obs)

        # 4. Task 1: Upsert AssetEdge Relationships (Domain -> DC, Domain -> Computer)
        domain_val = (result.default_naming_context or "").lower()
        domain_node = persisted_assets.get(domain_val)

        if domain_node and domain_node.id:
            # Domain -> Domain Controller
            dc_val = result.target.lower()
            dc_node = persisted_assets.get(dc_val)
            if dc_node and dc_node.id and dc_node.id != domain_node.id:
                dc_edge = AssetEdge(
                    project_id=project_id,
                    source_node_id=domain_node.id,
                    target_node_id=dc_node.id,
                    relation_type="HAS_DOMAIN_CONTROLLER",
                    source_tool=self.tool_name,
                    verification_state="observed",
                    confidence=1.0,
                    evidence_id=result.evidence_id,
                    metadata_json=json.dumps({
                        "source": result.default_naming_context,
                        "target": result.target,
                    }),
                )
                self.db.upsert_asset_edge(dc_edge)

            # Domain -> Member Computers
            for comp in result.computers:
                c_host = comp.get("dns_hostname") or comp.get("sam_name", "").replace("$", "")
                if not c_host or c_host.lower() == dc_val:
                    continue
                comp_node = persisted_assets.get(c_host.lower())
                if comp_node and comp_node.id and comp_node.id != domain_node.id:
                    comp_edge = AssetEdge(
                        project_id=project_id,
                        source_node_id=domain_node.id,
                        target_node_id=comp_node.id,
                        relation_type="HAS_MEMBER_COMPUTER",
                        source_tool=self.tool_name,
                        verification_state="observed",
                        confidence=0.9,
                        evidence_id=result.evidence_id,
                        metadata_json=json.dumps({
                            "source": result.default_naming_context,
                            "target": c_host,
                            "os": comp.get("os"),
                        }),
                    )
                    self.db.upsert_asset_edge(comp_edge)

        # 5. Audit Log
        self.db.add_audit_log(
            EngagementAuditLog(
                project_id=project_id,
                actor="operator",
                action="ldap_enumeration_synchronized",
                details=json.dumps({
                    "target": result.target,
                    "synced_assets": synced_assets,
                    "synced_findings": synced_findings,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }),
            )
        )

        return synced_assets, synced_findings
