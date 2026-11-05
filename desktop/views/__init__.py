"""Desktop Views for CyberSecuritySuite."""

from desktop.views.assets_view import AssetsView
from desktop.views.dashboard_view import DashboardView
from desktop.views.findings_view import FindingsView
from desktop.views.network_scan_view import NetworkScanView
from desktop.views.osint_view import OSINTView
from desktop.views.projects_view import ProjectsView
from desktop.views.reports_view import ReportsView
from desktop.views.visualization_workspace import VisualizationWorkspace
from desktop.views.web_scan_view import WebScanView

__all__ = [
    "AssetsView",
    "DashboardView",
    "FindingsView",
    "NetworkScanView",
    "OSINTView",
    "ProjectsView",
    "ReportsView",
    "VisualizationWorkspace",
    "WebScanView",
]

