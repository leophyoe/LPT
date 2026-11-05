"""Script to capture AI Assistant screenshots across Dark and Light modes."""
import os
import sys
from pathlib import Path

os.environ["QT_QPA_PLATFORM"] = "offscreen"

from PySide6.QtCore import QSize, Qt
from PySide6.QtWidgets import QApplication

from desktop.main_window import MainWindow
from desktop.theme import ThemeManager, ThemeMode
from desktop.views.ai_chat_view import AIChatView
from storage.db import Database

OUTPUT_DIR = Path("docs/audit/screenshots/ai_chat")
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

app = QApplication.instance() or QApplication(sys.argv)

db = Database(Path("/tmp/lpt_audit.db"))
projects = db.list_projects()
active_proj = projects[0] if projects else None

SAMPLE_USER_PROMPT = "Recommend stealth scan commands for perimeter subnet 10.10.10.0/24 with OS and service detection."
SAMPLE_ASSISTANT_REPLY = """### 🛡️ Recommended Stealth Enumeration Workflow

To map active perimeter assets while evading stateful firewall rate-limiting, execute a staged TCP SYN scan with packet fragmentation and timing template **T2** or **T3**:

```bash
# High-stealth TCP SYN scan with service version probe
nmap -sS -sV -Pn -T3 --top-ports 1000 -f 10.10.10.0/24 -oA evidence/nmap_perimeter_stealth
```

**Key Execution Parameters:**
- `-sS`: Half-open SYN scan minimizes socket establishment logging.
- `-Pn`: Treats all hosts as online to circumvent ICMP echo blocking.
- `-f`: Fragments probe packets to hinder packet inspection filters.
- `-sV`: Probes open ports to identify application banners and versions.

*Click `[ 📋 Copy Code ]` to copy the command directly or click below to load into the Command Console.*
"""


def capture(stage_prefix="before"):
    for mode, mode_name in [(ThemeMode.DARK, "dark"), (ThemeMode.LIGHT, "light")]:
        ThemeManager.instance().set_theme_mode(mode)
        app.processEvents()

        # 1. Standalone / Panel AI Chat View (Clean Empty State)
        chat_empty = AIChatView(db=db)
        if active_proj:
            chat_empty.set_active_project(active_proj)
            chat_empty.set_current_workspace("Assessment")
        chat_empty.resize(460, 800)
        chat_empty.show()
        app.processEvents()

        empty_path = OUTPUT_DIR / f"{stage_prefix}_empty_{mode_name}.png"
        chat_empty.grab().save(str(empty_path))
        print(f"Saved: {empty_path}")
        chat_empty.close()

        # 2. Standalone / Panel AI Chat View (Active Conversation with Code Blocks & Actions)
        chat_view = AIChatView(db=db)
        if active_proj:
            chat_view.set_active_project(active_proj)
            chat_view.set_current_workspace("Assessment")
        chat_view.resize(460, 800)
        chat_view.show()
        app.processEvents()

        # Populate conversation
        chat_view._append_message("user", SAMPLE_USER_PROMPT)
        chat_view._append_message("assistant", SAMPLE_ASSISTANT_REPLY, "builtin_offline")
        cmds = chat_view.extract_shell_commands(SAMPLE_ASSISTANT_REPLY)
        chat_view._update_commands_shelf(cmds)
        app.processEvents()

        conv_path = OUTPUT_DIR / f"{stage_prefix}_{mode_name}.png"
        chat_view.grab().save(str(conv_path))
        print(f"Saved: {conv_path}")
        chat_view.close()

        # 3. Docked in MainWindow
        window = MainWindow(db=db)
        window.resize(1360, 840)
        if active_proj:
            window._on_project_selected(active_proj)
        window.ai_chat_view._append_message("user", SAMPLE_USER_PROMPT)
        window.ai_chat_view._append_message("assistant", SAMPLE_ASSISTANT_REPLY, "builtin_offline")
        window.ai_chat_view._update_commands_shelf(cmds)
        window.show()
        app.processEvents()

        docked_path = OUTPUT_DIR / f"{stage_prefix}_docked_{mode_name}.png"
        window.grab().save(str(docked_path))
        print(f"Saved: {docked_path}")
        window.close()


if __name__ == "__main__":
    stage = sys.argv[1] if len(sys.argv) > 1 else "after"
    capture(stage)
