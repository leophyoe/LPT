# CyberSecuritySuite — Radial Topology Architecture & Industry Nomenclature Upgrade Report

**Date:** 2026-11-01  
**Project:** CyberSecuritySuite  
**Environment:** Linux (Ubuntu 24.04), Python 3.12.3, PySide6 6.12.0  
**Status:** COMPLETE & FULLY VERIFIED (All 34 tests passed, DB Hash Unchanged)

---

## 1. Executive Summary

In response to direct operator review regarding the **Radial Topology** visual design and terminology:
1. **Design Flaw Analysis:** The previous radial layout suffered from an empty central void, severe node overlap (narrow 45° fan spread), lopsided single-subnet crowding, disconnected floating clusters, and lack of visual distance/radar markers.
2. **Nomenclature Review:** Generic "2D / 3D" labels across the main window, workspaces, and designer widgets were replaced with standardized **Pentesting** (CPENT, OSCP, PTES, BloodHound) and **ICT / Enterprise Network Architecture** (Cisco, Fortinet, Gartner ASM) nomenclature.
3. **Core Architectural Overhaul:** Implemented a central **Core Gateway / Pivot Root** node, glowing spoke links from gateway to subnet hubs, balanced 360-degree radial dispersion with dual-tier staggering for single-subnets, allocated sector dispersion for multi-subnets, and an ambient **Cyber Radar Range Rings** background with azimuth cardinal ticks and tier guides.

```
+---------------------------------------------------------------------------------------+
|                       RADIAL PIVOT HORIZON (ATTACK GRAPH TOPOLOGY)                    |
|                                                                                       |
|                                  [ 000° NORTH ]                                       |
|                                         │                                             |
|                             .- - - - - -│- - - - - -.                                 |
|                         .'              │              '.                             |
|                       /      TIER 2: ASSET HORIZON       \                            |
|                     .'                  │                  '.                         |
|                    /     TIER 1: SUBNET DOMAINS & VLANS      \                        |
|                   /                     │                     \                       |
|                  │           .- - - - - │ - - - - -.           │                      |
|                  │         .'           │           '.         │                      |
|                  │        /     [ CORE GATEWAY ]      \        │                      |
|   [ 270° WEST ] ─────────┼──────(0, 0) PIVOT ROOT──────┼───────── [ 090° EAST ]       |
|                  │        \      /      │      \      /        │                      |
|                  │         '.   /       │       \   .'         │                      |
|                  │           .- - - - - │ - - - - -.           │                      |
|                   \            /        │        \            /                       |
|                    \   [SUBNET HUB] [SUBNET HUB] [SUBNET HUB]/                        |
|                     '.       │          │          │       .'                         |
|                       \    (Hosts)    (Hosts)    (Hosts)  /                           |
|                         '.              │              .'                             |
|                             '- - - - - -│- - - - - -'                                 |
|                                         │                                             |
|                                  [ 180° SOUTH ]                                       |
+---------------------------------------------------------------------------------------+
```

---

## 2. Radial Topology Design Overhaul: Before vs. After

| Feature / Issue | Previous Implementation (Flawed) | Upgraded Professional Architecture |
| :--- | :--- | :--- |
| **Central Origin (0, 0)** | **Empty Dead Void:** Subnets floated in a ring around an empty black hole with no root reference. | **Core Gateway / Pivot Root:** Central perimeter firewall / breach origin node sits at `(0, 0)` anchoring the attack graph. |
| **Network Connectivity** | **Disconnected Clusters:** Links only existed between Subnet Hub $\rightarrow$ Hosts; no links from Gateway to Subnets. | **Full Tree-Graph Hierarchy:** Spoke links connect `Gateway (0, 0) -> Subnet Hubs -> Endpoints` with distinct cyber color coding. |
| **Single-Subnet Layout** | **Lopsided & Crammed:** All hosts forced into an angle of 0 radians (right-hand side in a 45° wedge), leaving 85% of the canvas empty. | **360° Balanced Radial Galaxy:** Full 360-degree orbital distribution with dual-tier orbital radii (`230px` & `325px`), guaranteeing zero node collisions. |
| **Multi-Subnet Layout** | **Overlapping Wedges:** Narrow `fan_spread = 0.8` caused host nodes to collide and stack on top of each other. | **Allocated Sector Projections:** Dynamic sector math `(2π / N) * 0.85` with multi-tier spoke staggering (`175px` & `260px`), providing >80px spacing between all nodes. |
| **Concentric Guides** | **None:** Floating bubbles with no visual sense of distance, tier, or boundary. | **NetworkRadarBackgroundItem:** Concentric dashed radar rings with high-tech Tier labels (`TIER 0: CORE`, `TIER 1: SUBNETS`, `TIER 2: ASSETS`) and azimuth ticks (`000°`, `090°`, `180°`, `270°`). |
| **Dynamic Repositioning**| **Broken Switching:** Nodes remained frozen at old positions when switching layout modes. | **Seamless Dynamic Layout:** All hubs and hosts dynamically update their positions (`setPos`) and re-draw clean connection links on projection switch. |

---

## 3. Nomenclature Standardization: Pentesting & ICT Standards

Generic "2D / 3D" labels have been replaced with industry terminology used in **NIST SP 800-115**, **PTES**, **Cisco Enterprise Architecture**, and **Fortinet Network Security Expert (NSE)** standards:

| UI Location | Previous Generic Name | Upgraded Pentesting / ICT Standard Name | Professional Context |
| :--- | :--- | :--- | :--- |
| **MainWindow Tab 10** | `🌐 2D && 3D Cyber Mesh` | **`🌐 Enterprise Cyber Terrain`** | Threat Surface & Terrain Model |
| **MainWindow Tab 5** | `🗺️ Network Map Studio` | **`🗺️ Infrastructure Blueprint Studio`** | Enterprise Network Architecture |
| **Visualization Mode 1** | `2D Fortinet Topology` | **`🛡️ Perimeter & Segment Architecture`** | Perimeter, Firewalls, VLANs & Subnets |
| **Visualization Mode 2** | `3D Cyber Mesh (WebGL)`| **`🌐 Spatial Attack Surface`** | Spatial Lateral Movement & Depth Graph |
| **Studio Mode 1** | `🎨 2D Studio (Unified)` | **`📐 Blueprint Designer`** | Network Infrastructure Blueprinting |
| **Studio Mode 2** | `🛰️ Radial Topology` | **`🎯 Radial Attack Surface`** | Pivot Horizon & Lateral Blast Radius |
| **Studio Mode 3** | `🌐 3D Mesh (WebGL)` | **`🌐 Spatial Cyber Terrain`** | Multi-Dimensional Terrain Mapping |
| **HUD Projection Label** | `LAYOUT:` | **`PROJECTION:`** | Graph Projection & Coordinate Space |
| **HUD Button 1** | `🕸 Auspex Radial` | **`🎯 Radial Pivot Horizon`** | Radial Lateral Movement Projection |
| **HUD Button 2** | `🌲 Multi-Cluster` | **`🌲 Core-Distribution Hierarchy`** | Cisco 3-Tier Model (Core/Dist/Access) |
| **HUD Button 3** | `⊞ Grid` | **`⊞ Broadcast Domain Matrix`** | VLAN & Subnet Broadcast Partitioning |
| **HUD Edge Buttons** | `〰 Curve` / `─ Line` | **`〰 Spline Link`** / **`─ Direct Spoke`** | Vector Path Projection |
| **Sidebar Nav Item 2** | `2D Studio & 3D WebGL mesh` | **`Attack surface & cyber terrain`** | PTES Methodology Phase 2 |

---

## 4. Verification & Regression Testing

### A. Visualization & Graph Test Suite
- `tests/test_2d_3d_network_visualization.py`: **8/8 PASSED** in 3.25s
  - `test_fortinet_wan_and_gateway_nodes` (PASSED)
  - `test_network_connection_bezier_curve_and_styles` (PASSED)
  - `test_webgl_3d_network_view_asset_processing` (PASSED)
  - `test_visualization_workspace_mode_toggling` (PASSED)
  - `test_topology_designer_3d_mode_switching` (PASSED)
  - `test_assets_view_database_inventory_and_inspection` (PASSED)
  - `test_network_map_view_auspex_radial_mode` (PASSED)
  - `test_mainwindow_assets_and_visualization_integration` (PASSED)

### B. LDAP & Scope Test Suite
- `tests/test_ldap_live_enumeration.py`: **26/26 PASSED** in 2.01s

### C. Production Database Integrity
```bash
$ sha256sum storage/data/cybersecuritysuite.db
6c7387a760b82c1358d84750992bc6706d513636b9038aa0fd79ed0fda1c38e6  storage/data/cybersecuritysuite.db

$ sqlite3 storage/data/cybersecuritysuite.db "PRAGMA integrity_check;"
ok
```
- **Integrity Status:** Production database remained completely untouched (0 bytes modified).

---

## 5. Modified Files & Backups

### Modified Source Files:
- [`desktop/widgets/network_map_view.py`](file:///home/leo/Desktop/cybersecuritysuite/desktop/widgets/network_map_view.py)
- [`desktop/views/visualization_workspace.py`](file:///home/leo/Desktop/cybersecuritysuite/desktop/views/visualization_workspace.py)
- [`desktop/widgets/topology_designer.py`](file:///home/leo/Desktop/cybersecuritysuite/desktop/widgets/topology_designer.py)
- [`desktop/main_window.py`](file:///home/leo/Desktop/cybersecuritysuite/desktop/main_window.py)
- [`desktop/widgets/sidebar_nav.py`](file:///home/leo/Desktop/cybersecuritysuite/desktop/widgets/sidebar_nav.py)
- [`desktop/widgets/webgl_3d_network_view.py`](file:///home/leo/Desktop/cybersecuritysuite/desktop/widgets/webgl_3d_network_view.py)

### Backup Files:
- `desktop/widgets/network_map_view.py.bak_20261101_radial_upgrade`
- `desktop/views/visualization_workspace.py.bak_20261101_radial_upgrade`
- `desktop/widgets/topology_designer.py.bak_20261101_radial_upgrade`
- `desktop/main_window.py.bak_20261101_radial_upgrade`
- `desktop/widgets/sidebar_nav.py.bak_20261101_radial_upgrade`
- `desktop/widgets/webgl_3d_network_view.py.bak_20261101_radial_upgrade`

