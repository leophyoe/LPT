"""Google Dorking Query Engine & OSINT Helper Widget for CyberSecuritySuite.

Implements standard Passive Information Gathering workflows based on the
INE Penetration Testing Methodology:
1. Target Domain & Scope Binding (automatically extracts from active engagement).
2. Categorized Dork Library covering:
   - Sensitive Files & Backups (.env, .sql, .bak, .git, private keys, logs)
   - Admin & Authentication Portals (admin panels, SSO, OAuth, webmail)
   - Information Disclosure & Indexing (Index of /, phpinfo, Swagger API docs)
   - Cloud Storage & Leaks (AWS S3, Azure Blobs, GCP Storage, Pastebin, GitHub)
   - Subdomains & Infrastructure (subdomains, dev/stage environments, VPNs)
   - Threat Intelligence & Search Engines (Shodan, Censys, crt.sh, VirusTotal, Wayback)
3. 1-Click Copy and 1-Click Browser Launch for every query.
4. Custom Dork Builder for composing on-the-fly search strings.
5. Passive DNS & Technology Recon quick lookups.
"""

from __future__ import annotations

import logging
import urllib.parse
from dataclasses import dataclass
from typing import Dict, List, Optional

from PySide6.QtCore import QSize, Qt, QUrl, Signal
from PySide6.QtGui import QColor, QDesktopServices, QFont, QIcon
from PySide6.QtWidgets import (
    QApplication,
    QButtonGroup,
    QComboBox,
    QFrame,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from storage.db import Database
from storage.models import Project

logger = logging.getLogger(__name__)


@dataclass
class GoogleDorkItem:
    category: str
    title: str
    description: str
    query_template: str
    severity: str = "MEDIUM"  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    search_engine: str = "Google"  # Google, Shodan, Censys, crt.sh, VirusTotal


# Pre-curated, high-value pentester dork library
PREBUILT_DORKS: List[GoogleDorkItem] = [
    # --- Category: Sensitive Files & Backups ---
    GoogleDorkItem(
        category="Sensitive Files",
        title="Environment & Config Files (.env)",
        description="Exposed .env configuration files containing database credentials and secret API keys.",
        query_template="site:{domain} filetype:env | intext:DB_PASSWORD | intext:APP_KEY",
        severity="CRITICAL",
    ),
    GoogleDorkItem(
        category="Sensitive Files",
        title="SQL Database Dumps",
        description="Unprotected raw SQL database backups, dumps, and schema tables.",
        query_template="site:{domain} filetype:sql | filetype:dump | filetype:db | intext:\"INSERT INTO\"",
        severity="CRITICAL",
    ),
    GoogleDorkItem(
        category="Sensitive Files",
        title="Backup & Compressed Archives",
        description="Archive files (.zip, .bak, .old, .tgz, .tar.gz) often left on web servers.",
        query_template="site:{domain} filetype:bak | filetype:backup | filetype:old | filetype:zip | filetype:tgz",
        severity="HIGH",
    ),
    GoogleDorkItem(
        category="Sensitive Files",
        title="Private Keys & TLS Certificates",
        description="Unencrypted RSA private keys, PGP keys, or PEM certificates.",
        query_template="site:{domain} intext:\"BEGIN RSA PRIVATE KEY\" | intext:\"BEGIN PRIVATE KEY\" | filetype:pem",
        severity="CRITICAL",
    ),
    GoogleDorkItem(
        category="Sensitive Files",
        title="Log Files & Error Traces",
        description="Application runtime logs, error logs, and debug dumps exposing internal structures.",
        query_template="site:{domain} filetype:log | intext:\"error.log\" | intext:\"debug.log\" | intext:\"access.log\"",
        severity="HIGH",
    ),
    GoogleDorkItem(
        category="Sensitive Files",
        title="Git & Version Control Exposure",
        description="Exposed .git or .svn directory metadata allowing source code extraction.",
        query_template="site:{domain} inurl:\".git/config\" | inurl:\".git/HEAD\" | inurl:\".svn/entries\"",
        severity="CRITICAL",
    ),
    GoogleDorkItem(
        category="Sensitive Files",
        title="Configuration Files (YAML/INI/XML)",
        description="Application configuration files containing credentials or endpoints.",
        query_template="site:{domain} filetype:yml | filetype:yaml | filetype:ini | filetype:conf intext:password",
        severity="HIGH",
    ),

    # --- Category: Admin & Login Portals ---
    GoogleDorkItem(
        category="Admin & Logins",
        title="Administrative Login Portals",
        description="Web administrator interfaces, backend dashboards, and control panels.",
        query_template="site:{domain} inurl:admin | inurl:login | inurl:portal | inurl:cpanel | inurl:wp-login.php",
        severity="HIGH",
    ),
    GoogleDorkItem(
        category="Admin & Logins",
        title="Dashboard & Control Panels",
        description="Administrative dashboards and monitoring control panels.",
        query_template="site:{domain} intitle:\"Dashboard\" | intitle:\"Admin Console\" | intitle:\"Control Panel\"",
        severity="MEDIUM",
    ),
    GoogleDorkItem(
        category="Admin & Logins",
        title="Single Sign-On & OAuth Endpoints",
        description="SSO login portals, Okta, SAML, and OAuth authorization endpoints.",
        query_template="site:{domain} inurl:oauth | inurl:saml | inurl:sso | inurl:auth | inurl:openid",
        severity="MEDIUM",
    ),
    GoogleDorkItem(
        category="Admin & Logins",
        title="Webmail & Exchange OWA",
        description="Corporate webmail portals (Roundcube, Microsoft Outlook Web Access, Horde).",
        query_template="site:{domain} inurl:webmail | inurl:roundcube | inurl:owa | inurl:exchange",
        severity="MEDIUM",
    ),

    # --- Category: Information Disclosure & Indexing ---
    GoogleDorkItem(
        category="Info Disclosure",
        title="Directory Indexing (Index of /)",
        description="Web servers with auto-indexing enabled, exposing unlinked files and directories.",
        query_template="site:{domain} intitle:\"Index of /\" | intitle:\"Index of /uploads\" | intitle:\"Index of /backup\"",
        severity="HIGH",
    ),
    GoogleDorkItem(
        category="Info Disclosure",
        title="Server Status & Info Pages",
        description="Apache/Nginx server status, server-info, or PHP phpinfo() diagnostic pages.",
        query_template="site:{domain} inurl:server-status | inurl:server-info | inurl:phpinfo.php | intext:\"PHP Version\"",
        severity="HIGH",
    ),
    GoogleDorkItem(
        category="Info Disclosure",
        title="API Documentation (Swagger / GraphQL)",
        description="Interactive Swagger, OpenAPI, ReDoc, or GraphQL playground documentation endpoints.",
        query_template="site:{domain} inurl:swagger | inurl:api-docs | inurl:\"graphql\" | inurl:redoc",
        severity="MEDIUM",
    ),
    GoogleDorkItem(
        category="Info Disclosure",
        title="GitHub / GitLab Public Leaks",
        description="Public repositories leaking credentials, tokens, or confidential API keys for the target.",
        query_template="site:github.com \"{domain}\" password | secret | token | api_key | private_key",
        severity="CRITICAL",
    ),

    # --- Category: Cloud Storage & Leaks ---
    GoogleDorkItem(
        category="Cloud Storage",
        title="Amazon S3 Buckets Exposure",
        description="Misconfigured, publicly indexed AWS S3 storage buckets referencing target domain.",
        query_template="site:s3.amazonaws.com \"{domain}\" | site:amazonaws.com \"{domain}\"",
        severity="HIGH",
    ),
    GoogleDorkItem(
        category="Cloud Storage",
        title="Azure Blob Storage Containers",
        description="Publicly readable Azure Blob containers storing documents, backups, or exports.",
        query_template="site:blob.core.windows.net \"{domain}\"",
        severity="HIGH",
    ),
    GoogleDorkItem(
        category="Cloud Storage",
        title="Google Cloud Storage Buckets",
        description="Publicly accessible GCP storage buckets for the target.",
        query_template="site:storage.googleapis.com \"{domain}\"",
        severity="HIGH",
    ),
    GoogleDorkItem(
        category="Cloud Storage",
        title="Pastebin & Dump Sites",
        description="Target domain mentions on Pastebin, Throwbin, and paste sites indicating leaked data.",
        query_template="site:pastebin.com \"{domain}\" | site:throwbin.io \"{domain}\"",
        severity="HIGH",
    ),

    # --- Category: Subdomains & Infrastructure ---
    GoogleDorkItem(
        category="Subdomains",
        title="Subdomain Enumeration via Search",
        description="Passive discovery of indexed subdomains excluding primary www hostname.",
        query_template="site:*.{domain} -www.{domain}",
        severity="LOW",
    ),
    GoogleDorkItem(
        category="Subdomains",
        title="Staging & Development Environments",
        description="Exposed pre-production, staging, test, and UAT server instances.",
        query_template="site:dev.{domain} | site:stage.{domain} | site:test.{domain} | site:uat.{domain} | site:qa.{domain}",
        severity="HIGH",
    ),
    GoogleDorkItem(
        category="Subdomains",
        title="VPN & Remote Access Infrastructure",
        description="Citrix, Pulse Secure, GlobalProtect, and Cisco AnyConnect remote access gateways.",
        query_template="site:vpn.{domain} | site:remote.{domain} | site:citrix.{domain} | site:portal.{domain}",
        severity="HIGH",
    ),

    # --- Category: Threat Intel & OSINT Direct Search ---
    GoogleDorkItem(
        category="Threat Intel",
        title="Shodan Host Intelligence",
        description="Shodan Internet-wide scan results, banners, open ports, and vulnerabilities.",
        query_template="https://www.shodan.io/search?query=hostname:{domain}",
        severity="INFO",
        search_engine="Shodan",
    ),
    GoogleDorkItem(
        category="Threat Intel",
        title="Censys Attack Surface Search",
        description="Censys global scan data and verified TLS certificate identities.",
        query_template="https://search.censys.io/search?resource=hosts&q={domain}",
        severity="INFO",
        search_engine="Censys",
    ),
    GoogleDorkItem(
        category="Threat Intel",
        title="crt.sh Certificate Transparency",
        description="Complete public Certificate Transparency log of all SSL/TLS certificates issued.",
        query_template="https://crt.sh/?q=%25.{domain}",
        severity="INFO",
        search_engine="crt.sh",
    ),
    GoogleDorkItem(
        category="Threat Intel",
        title="VirusTotal Domain Telemetry",
        description="Malware detections, communicating files, WHOIS, and DNS resolutions.",
        query_template="https://www.virustotal.com/gui/domain/{domain}",
        severity="INFO",
        search_engine="VirusTotal",
    ),
    GoogleDorkItem(
        category="Threat Intel",
        title="Wayback Machine Historical Archive",
        description="Historical web snapshots to locate deprecated endpoints and removed sensitive files.",
        query_template="https://web.archive.org/web/*/{domain}/*",
        severity="INFO",
        search_engine="Wayback",
    ),
]


class GoogleDorkWidget(QWidget):
    """Interactive Google Dorking Engine & Passive Reconnaissance Workspace."""

    dork_copied = Signal(str)
    search_launched = Signal(str)

    def __init__(self, db: Optional[Database] = None, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.db = db
        self.active_project: Optional[Project] = None
        self.current_domain: str = "example.com"
        self._dorks: List[GoogleDorkItem] = list(PREBUILT_DORKS)
        self.setObjectName("googleDorkWidget")
        self._init_ui()

    def set_active_project(self, project: Optional[Project]):
        """Sets the active project and binds the target domain."""
        self.active_project = project
        if project:
            # Check if project target scope has a domain
            domain = self._resolve_target_domain(project)
            if domain:
                self.set_target_domain(domain)
            self.lbl_project_badge.setText(f"🎯 Target: {self.current_domain}  [{project.name}]")
            self.lbl_project_badge.setStyleSheet(
                "background-color: #172554; color: #60a5fa; border: 1px solid #1d4ed8; border-radius: 4px; padding: 4px 10px; font-weight: bold; font-size: 11px;"
            )
        else:
            self.lbl_project_badge.setText("🎯 Target: No Project Bound")
            self.lbl_project_badge.setStyleSheet(
                "background-color: #1e293b; color: #94a3b8; border: 1px solid #334155; border-radius: 4px; padding: 4px 10px; font-size: 11px;"
            )

    def _resolve_target_domain(self, project: Project) -> Optional[str]:
        if not self.db:
            return None
        try:
            scopes = self.db.list_scopes(project.id)
            for sc in scopes:
                val = getattr(sc, "target", "")
                if val and "." in val and not val.replace(".", "").isdigit() and "/" not in val:
                    return val
            # Fallback to asset nodes
            assets = self.db.list_asset_nodes(project.id)
            for a in assets:
                if a.node_type in ("domain", "subdomain") and "." in a.value:
                    parts = a.value.split(".")
                    if len(parts) >= 2:
                        return ".".join(parts[-2:])
        except Exception as exc:
            logger.debug("Error resolving target domain: %s", exc)
        return None

    def set_target_domain(self, domain: str):
        """Updates the active target domain across all queries."""
        domain = domain.strip().lower()
        if not domain:
            return
        # Clean protocol or slashes if user pasted a URL
        if "://" in domain:
            domain = domain.split("://")[1]
        domain = domain.split("/")[0].split(":")[0]
        self.current_domain = domain
        self.txt_domain.setText(domain)
        self._refresh_dork_table()
        self._update_custom_builder_preview()

    def _init_ui(self):
        root_layout = QVBoxLayout(self)
        root_layout.setContentsMargins(12, 10, 12, 10)
        root_layout.setSpacing(10)

        # -------------------------------------------------------------
        # 1. Header & Target Domain Configuration Bar
        # -------------------------------------------------------------
        header_frame = QFrame()
        header_frame.setStyleSheet(
            "QFrame { background-color: #0f172a; border: 1px solid #1e293b; border-radius: 8px; padding: 6px; }"
        )
        h_layout = QHBoxLayout(header_frame)
        h_layout.setContentsMargins(10, 6, 10, 6)
        h_layout.setSpacing(12)

        title_box = QVBoxLayout()
        title_box.setSpacing(2)
        lbl_title = QLabel("🔎  Google Dorking Engine & Search OSINT")
        lbl_title.setFont(QFont("Segoe UI", 13, QFont.Bold))
        lbl_title.setStyleSheet("color: #38bdf8;")
        lbl_sub = QLabel("Passive reconnaissance, exposed credentials, indexing, and threat intelligence shortcuts.")
        lbl_sub.setStyleSheet("color: #94a3b8; font-size: 11px;")
        title_box.addWidget(lbl_title)
        title_box.addWidget(lbl_sub)
        h_layout.addLayout(title_box)

        h_layout.addStretch()

        # Target Domain Input
        lbl_dom = QLabel("Target Domain:")
        lbl_dom.setFont(QFont("Segoe UI", 11, QFont.Bold))
        lbl_dom.setStyleSheet("color: #cbd5e1;")
        h_layout.addWidget(lbl_dom)

        self.txt_domain = QLineEdit()
        self.txt_domain.setPlaceholderText("e.g. acme.com")
        self.txt_domain.setText(self.current_domain)
        self.txt_domain.setFixedWidth(180)
        self.txt_domain.setStyleSheet(
            "QLineEdit { background-color: #111827; color: #f8fafc; border: 1px solid #334155; border-radius: 6px; padding: 6px 10px; font-weight: bold; font-size: 12px; }"
            "QLineEdit:focus { border-color: #38bdf8; }"
        )
        self.txt_domain.returnPressed.connect(lambda: self.set_target_domain(self.txt_domain.text()))
        h_layout.addWidget(self.txt_domain)

        btn_apply_domain = QPushButton("Apply Target")
        btn_apply_domain.setCursor(Qt.PointingHandCursor)
        btn_apply_domain.setStyleSheet(
            "QPushButton { background-color: #0284c7; color: #ffffff; border: 1px solid #38bdf8; border-radius: 6px; padding: 6px 12px; font-weight: bold; font-size: 11px; }"
            "QPushButton:hover { background-color: #0ea5e9; }"
        )
        btn_apply_domain.clicked.connect(lambda: self.set_target_domain(self.txt_domain.text()))
        h_layout.addWidget(btn_apply_domain)

        self.lbl_project_badge = QLabel("🎯 Target: Standalone")
        self.lbl_project_badge.setStyleSheet(
            "background-color: #1e293b; color: #94a3b8; border: 1px solid #334155; border-radius: 4px; padding: 4px 10px; font-size: 11px;"
        )
        h_layout.addWidget(self.lbl_project_badge)

        root_layout.addWidget(header_frame)

        # -------------------------------------------------------------
        # 2. Controls & Filter Bar
        # -------------------------------------------------------------
        ctrl_bar = QHBoxLayout()
        ctrl_bar.setSpacing(10)

        # Category Filter Dropdown
        lbl_cat = QLabel("Category:")
        lbl_cat.setStyleSheet("color: #94a3b8; font-weight: 600; font-size: 11px;")
        ctrl_bar.addWidget(lbl_cat)

        self.combo_category = QComboBox()
        self.combo_category.addItem("All Categories (30+)")
        self.combo_category.addItem("📂 Sensitive Files & Backups", "Sensitive Files")
        self.combo_category.addItem("🔑 Admin & Login Portals", "Admin & Logins")
        self.combo_category.addItem("📋 Info Disclosure & Indexing", "Info Disclosure")
        self.combo_category.addItem("☁️ Cloud Storage & Leaks", "Cloud Storage")
        self.combo_category.addItem("🌐 Subdomains & Infrastructure", "Subdomains")
        self.combo_category.addItem("🔍 Threat Intel & Search Engines", "Threat Intel")
        self.combo_category.setStyleSheet(
            "QComboBox { background-color: #111827; color: #f8fafc; border: 1px solid #334155; border-radius: 6px; padding: 5px 12px; font-size: 11px; }"
            "QComboBox QAbstractItemView { background-color: #0f172a; color: #f8fafc; selection-background-color: #1e293b; }"
        )
        self.combo_category.currentIndexChanged.connect(self._refresh_dork_table)
        ctrl_bar.addWidget(self.combo_category)

        # Search Query / Filter
        self.txt_filter = QLineEdit()
        self.txt_filter.setPlaceholderText("🔍  Filter dorks by keyword (e.g. .env, admin, s3, git)...")
        self.txt_filter.setStyleSheet(
            "QLineEdit { background-color: #111827; color: #f8fafc; border: 1px solid #334155; border-radius: 6px; padding: 5px 10px; font-size: 11px; }"
            "QLineEdit:focus { border-color: #38bdf8; }"
        )
        self.txt_filter.textChanged.connect(self._refresh_dork_table)
        ctrl_bar.addWidget(self.txt_filter, stretch=1)

        # Stats Badge
        self.lbl_stats = QLabel("Showing 0 dorks")
        self.lbl_stats.setStyleSheet("color: #38bdf8; font-weight: bold; font-size: 11px;")
        ctrl_bar.addWidget(self.lbl_stats)

        root_layout.addLayout(ctrl_bar)

        # -------------------------------------------------------------
        # 3. Main Splitter: Dorks Table (Left/Top) & Custom Builder (Bottom)
        # -------------------------------------------------------------
        main_splitter = QSplitter(Qt.Orientation.Vertical)
        main_splitter.setStyleSheet("QSplitter::handle { background-color: #1e293b; height: 3px; }")

        # Table of Prebuilt Dorks
        self.table = QTableWidget()
        self.table.setColumnCount(5)
        self.table.setHorizontalHeaderLabels(["Category", "Severity", "Dork Objective & Title", "Search Query", "Actions"])
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeToContents)
        self.table.verticalHeader().setVisible(False)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setStyleSheet(
            "QTableWidget { background-color: #0b0f19; border: 1px solid #1e293b; border-radius: 6px; gridline-color: #161f30; font-size: 11px; color: #f1f5f9; }"
            "QHeaderView::section { background-color: #0f172a; color: #94a3b8; font-weight: bold; font-size: 10px; border: none; border-bottom: 1px solid #1e293b; padding: 6px; }"
            "QTableWidget::item:selected { background-color: #1e293b; color: #38bdf8; }"
        )
        main_splitter.addWidget(self.table)

        # Bottom Panel: Custom Dork Builder & Direct OSINT Shortcuts
        bottom_panel = self._build_custom_builder_panel()
        main_splitter.addWidget(bottom_panel)
        main_splitter.setStretchFactor(0, 7)
        main_splitter.setStretchFactor(1, 3)

        root_layout.addWidget(main_splitter, stretch=1)

        self._refresh_dork_table()

    def _build_custom_builder_panel(self) -> QWidget:
        panel = QFrame()
        panel.setStyleSheet(
            "QFrame { background-color: #0d1117; border: 1px solid #1e293b; border-radius: 8px; }"
        )
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(12, 10, 12, 10)
        layout.setSpacing(8)

        lbl_hdr = QLabel("🛠️  Interactive Custom Dork Builder & On-the-Fly Query Composer")
        lbl_hdr.setFont(QFont("Segoe UI", 11, QFont.Bold))
        lbl_hdr.setStyleSheet("color: #f8fafc;")
        layout.addWidget(lbl_hdr)

        # Builder inputs row
        row = QHBoxLayout()
        row.setSpacing(8)

        # site:
        row.addWidget(QLabel("site:"))
        self.bld_site = QLineEdit()
        self.bld_site.setPlaceholderText("domain.com")
        self.bld_site.setText(self.current_domain)
        self.bld_site.textChanged.connect(self._update_custom_builder_preview)
        self.bld_site.setStyleSheet("QLineEdit { background-color: #161b22; color: #fff; border: 1px solid #30363d; border-radius: 4px; padding: 4px; font-size: 11px; }")
        row.addWidget(self.bld_site, 1)

        # filetype:
        row.addWidget(QLabel("filetype:"))
        self.bld_filetype = QLineEdit()
        self.bld_filetype.setPlaceholderText("env, sql, bak")
        self.bld_filetype.textChanged.connect(self._update_custom_builder_preview)
        self.bld_filetype.setStyleSheet("QLineEdit { background-color: #161b22; color: #fff; border: 1px solid #30363d; border-radius: 4px; padding: 4px; font-size: 11px; }")
        row.addWidget(self.bld_filetype, 1)

        # inurl:
        row.addWidget(QLabel("inurl:"))
        self.bld_inurl = QLineEdit()
        self.bld_inurl.setPlaceholderText("admin, api, config")
        self.bld_inurl.textChanged.connect(self._update_custom_builder_preview)
        self.bld_inurl.setStyleSheet("QLineEdit { background-color: #161b22; color: #fff; border: 1px solid #30363d; border-radius: 4px; padding: 4px; font-size: 11px; }")
        row.addWidget(self.bld_inurl, 1)

        # intext:
        row.addWidget(QLabel("intext:"))
        self.bld_intext = QLineEdit()
        self.bld_intext.setPlaceholderText("password, secret")
        self.bld_intext.textChanged.connect(self._update_custom_builder_preview)
        self.bld_intext.setStyleSheet("QLineEdit { background-color: #161b22; color: #fff; border: 1px solid #30363d; border-radius: 4px; padding: 4px; font-size: 11px; }")
        row.addWidget(self.bld_intext, 1)

        # intitle:
        row.addWidget(QLabel("intitle:"))
        self.bld_intitle = QLineEdit()
        self.bld_intitle.setPlaceholderText("Index of /, Dashboard")
        self.bld_intitle.textChanged.connect(self._update_custom_builder_preview)
        self.bld_intitle.setStyleSheet("QLineEdit { background-color: #161b22; color: #fff; border: 1px solid #30363d; border-radius: 4px; padding: 4px; font-size: 11px; }")
        row.addWidget(self.bld_intitle, 1)

        layout.addLayout(row)

        # Preview & Action Row
        prev_row = QHBoxLayout()
        prev_row.setSpacing(8)

        lbl_prev = QLabel("Live Query:")
        lbl_prev.setStyleSheet("color: #94a3b8; font-weight: bold; font-size: 11px;")
        prev_row.addWidget(lbl_prev)

        self.txt_custom_preview = QLineEdit()
        self.txt_custom_preview.setReadOnly(True)
        self.txt_custom_preview.setStyleSheet(
            "QLineEdit { background-color: #090d16; color: #38bdf8; border: 1px solid #1e293b; border-radius: 4px; padding: 5px 10px; font-family: monospace; font-size: 11px; }"
        )
        prev_row.addWidget(self.txt_custom_preview, stretch=1)

        btn_copy_custom = QPushButton("📋 Copy Query")
        btn_copy_custom.setCursor(Qt.PointingHandCursor)
        btn_copy_custom.setStyleSheet(
            "QPushButton { background-color: #1e293b; color: #f1f5f9; border: 1px solid #334155; border-radius: 4px; padding: 5px 12px; font-size: 11px; font-weight: bold; }"
            "QPushButton:hover { background-color: #334155; }"
        )
        btn_copy_custom.clicked.connect(self._copy_custom_query)
        prev_row.addWidget(btn_copy_custom)

        btn_launch_custom = QPushButton("🚀 Search Google")
        btn_launch_custom.setCursor(Qt.PointingHandCursor)
        btn_launch_custom.setStyleSheet(
            "QPushButton { background-color: #0284c7; color: #ffffff; border: 1px solid #38bdf8; border-radius: 4px; padding: 5px 12px; font-size: 11px; font-weight: bold; }"
            "QPushButton:hover { background-color: #0ea5e9; }"
        )
        btn_launch_custom.clicked.connect(self._launch_custom_query)
        prev_row.addWidget(btn_launch_custom)

        layout.addLayout(prev_row)
        self._update_custom_builder_preview()
        return panel

    def _update_custom_builder_preview(self):
        parts = []
        domain = self.bld_site.text().strip() or self.current_domain
        if domain:
            parts.append(f"site:{domain}")
        if self.bld_filetype.text().strip():
            ft = self.bld_filetype.text().strip()
            parts.append(f"filetype:{ft}")
        if self.bld_inurl.text().strip():
            iu = self.bld_inurl.text().strip()
            parts.append(f"inurl:{iu}")
        if self.bld_intext.text().strip():
            it = self.bld_intext.text().strip()
            parts.append(f'intext:"{it}"')
        if self.bld_intitle.text().strip():
            iti = self.bld_intitle.text().strip()
            parts.append(f'intitle:"{iti}"')

        query = " ".join(parts) if parts else f"site:{self.current_domain}"
        self.txt_custom_preview.setText(query)

    def _copy_custom_query(self):
        query = self.txt_custom_preview.text().strip()
        if query:
            clipboard = QApplication.clipboard()
            clipboard.setText(query)
            self.dork_copied.emit(query)

    def _launch_custom_query(self):
        query = self.txt_custom_preview.text().strip()
        if query:
            self._launch_search_url("Google", query)

    def _refresh_dork_table(self):
        """Populates the table with filtered, formatted dorks."""
        selected_cat = self.combo_category.currentData()
        filter_text = self.txt_filter.text().strip().lower()

        filtered_dorks: List[GoogleDorkItem] = []
        for d in self._dorks:
            if selected_cat and d.category != selected_cat:
                continue
            formatted_query = d.query_template.replace("{domain}", self.current_domain)
            if filter_text:
                in_title = filter_text in d.title.lower()
                in_desc = filter_text in d.description.lower()
                in_query = filter_text in formatted_query.lower()
                in_cat = filter_text in d.category.lower()
                if not (in_title or in_desc or in_query or in_cat):
                    continue
            filtered_dorks.append(d)

        self.table.setRowCount(len(filtered_dorks))
        self.lbl_stats.setText(f"Showing {len(filtered_dorks)} of {len(self._dorks)} dorks")

        severity_colors = {
            "CRITICAL": ("#ef4444", "#450a0a"),
            "HIGH": ("#f97316", "#431407"),
            "MEDIUM": ("#eab308", "#422006"),
            "LOW": ("#3b82f6", "#172554"),
            "INFO": ("#06b6d4", "#083344"),
        }

        for row, dork in enumerate(filtered_dorks):
            formatted_query = dork.query_template.replace("{domain}", self.current_domain)

            # Col 0: Category
            item_cat = QTableWidgetItem(dork.category)
            item_cat.setTextAlignment(Qt.AlignCenter)
            item_cat.setForeground(QColor("#94a3b8"))
            self.table.setItem(row, 0, item_cat)

            # Col 1: Severity
            sev_fg, sev_bg = severity_colors.get(dork.severity, ("#94a3b8", "#1e293b"))
            item_sev = QTableWidgetItem(f" {dork.severity} ")
            item_sev.setTextAlignment(Qt.AlignCenter)
            item_sev.setForeground(QColor(sev_fg))
            item_sev.setBackground(QColor(sev_bg))
            self.table.setItem(row, 1, item_sev)

            # Col 2: Dork Title
            item_title = QTableWidgetItem(dork.title)
            item_title.setToolTip(dork.description)
            item_title.setForeground(QColor("#f8fafc"))
            item_title.setFont(QFont("Segoe UI", 10, QFont.Bold))
            self.table.setItem(row, 2, item_title)

            # Col 3: Search Query
            item_q = QTableWidgetItem(formatted_query)
            item_q.setFont(QFont("Monospace", 9))
            item_q.setForeground(QColor("#38bdf8"))
            item_q.setToolTip(f"Click Copy to copy: {formatted_query}")
            self.table.setItem(row, 3, item_q)

            # Col 4: Action Buttons (Copy & Launch)
            actions_widget = QWidget()
            act_layout = QHBoxLayout(actions_widget)
            act_layout.setContentsMargins(4, 2, 4, 2)
            act_layout.setSpacing(6)

            btn_copy = QPushButton("📋 Copy")
            btn_copy.setCursor(Qt.PointingHandCursor)
            btn_copy.setToolTip("Copy formatted dork to clipboard")
            btn_copy.setStyleSheet(
                "QPushButton { background-color: #1e293b; color: #f1f5f9; border: 1px solid #334155; border-radius: 4px; padding: 3px 8px; font-size: 10px; font-weight: bold; }"
                "QPushButton:hover { background-color: #334155; }"
            )
            # Bind copy
            btn_copy.clicked.connect(
                (lambda q=formatted_query, b=btn_copy: lambda: self._on_copy_dork(q, b))()
            )
            act_layout.addWidget(btn_copy)

            btn_launch = QPushButton(f"🚀 {dork.search_engine}")
            btn_launch.setCursor(Qt.PointingHandCursor)
            btn_launch.setToolTip(f"Launch query in {dork.search_engine}")
            btn_launch.setStyleSheet(
                "QPushButton { background-color: #0284c7; color: #ffffff; border: 1px solid #38bdf8; border-radius: 4px; padding: 3px 8px; font-size: 10px; font-weight: bold; }"
                "QPushButton:hover { background-color: #0ea5e9; }"
            )
            btn_launch.clicked.connect(
                (lambda eng=dork.search_engine, q=formatted_query: lambda: self._launch_search_url(eng, q))()
            )
            act_layout.addWidget(btn_launch)

            self.table.setCellWidget(row, 4, actions_widget)
            self.table.setRowHeight(row, 36)

    def _on_copy_dork(self, query: str, button: QPushButton):
        clipboard = QApplication.clipboard()
        clipboard.setText(query)
        self.dork_copied.emit(query)
        orig_text = button.text()
        button.setText("✓ Copied")
        button.setStyleSheet(
            "QPushButton { background-color: #064e3b; color: #34d399; border: 1px solid #047857; border-radius: 4px; padding: 3px 8px; font-size: 10px; font-weight: bold; }"
        )
        # Restore after 1.5 seconds safely
        from PySide6.QtCore import QTimer
        QTimer.singleShot(1500, lambda: self._restore_button(button, orig_text))

    def _restore_button(self, button: QPushButton, orig_text: str):
        try:
            button.setText(orig_text)
            button.setStyleSheet(
                "QPushButton { background-color: #1e293b; color: #f1f5f9; border: 1px solid #334155; border-radius: 4px; padding: 3px 8px; font-size: 10px; font-weight: bold; }"
                "QPushButton:hover { background-color: #334155; }"
            )
        except Exception:
            pass

    def _launch_search_url(self, search_engine: str, query: str):
        """Constructs target search engine URL and launches user's default browser."""
        if query.startswith("http://") or query.startswith("https://"):
            url = query
        elif search_engine == "Google":
            url = f"https://www.google.com/search?q={urllib.parse.quote(query)}"
        elif search_engine == "Shodan":
            url = f"https://www.shodan.io/search?query={urllib.parse.quote(query)}"
        elif search_engine == "Censys":
            url = f"https://search.censys.io/search?resource=hosts&q={urllib.parse.quote(query)}"
        elif search_engine == "crt.sh":
            url = f"https://crt.sh/?q={urllib.parse.quote(query)}"
        else:
            url = f"https://www.google.com/search?q={urllib.parse.quote(query)}"

        logger.info("Opening OSINT search query: %s", url)
        QDesktopServices.openUrl(QUrl(url))
        self.search_launched.emit(url)

