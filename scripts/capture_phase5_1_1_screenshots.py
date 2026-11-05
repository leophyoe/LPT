"""Capture verification screenshots for Phase 5.1.1 AI Assistant acceptance fixes."""

import os
import sys
from pathlib import Path

os.environ["QT_QPA_PLATFORM"] = "offscreen"

from PySide6.QtCore import QSize, Qt
from PySide6.QtWidgets import QApplication

from desktop.theme import ThemeManager, ThemeMode
from desktop.views.ai_chat_view import AIChatView
from storage.db import Database

OUTPUT_DIR = Path("docs/audit/screenshots/phase5_1_1")
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

app = QApplication.instance() or QApplication(sys.argv)

db = Database(Path("/tmp/lpt_audit.db"))
projects = db.list_projects()
active_proj = projects[0] if projects else None

SAMPLE_PROMPT = "Recommend stealth scan commands for perimeter subnet 10.10.10.0/24 with OS and service detection."
SAMPLE_REPLY = """### 🛡️ Recommended Stealth Enumeration Workflow

To map active perimeter assets while evading stateful firewall rate-limiting, execute a staged TCP SYN scan with packet fragmentation and timing template **T3**:

```bash
nmap -sS -sV -Pn -T3 --top-ports 1000 -f 10.10.10.0/24 -oA evidence/nmap_perimeter_stealth
```

**Key Execution Parameters:**
- `-sS`: Half-open SYN scan minimizes socket establishment logging.
- `-Pn`: Treats all hosts as online to circumvent ICMP echo blocking.
- `-f`: Fragments probe packets to hinder packet inspection filters.
- `-sV`: Probes open ports to identify application banners and versions.
"""


def capture_all():
    for mode, mode_name in [(ThemeMode.DARK, "dark"), (ThemeMode.LIGHT, "light")]:
        ThemeManager.instance().set_theme_mode(mode)
        app.processEvents()

        # 1. Empty State (Clean, no text)
        view_empty = AIChatView(db=db)
        if active_proj:
            view_empty.set_active_project(active_proj)
            view_empty.set_current_workspace("Assessment")
        view_empty.resize(460, 780)
        view_empty.show()
        app.processEvents()

        p_empty = OUTPUT_DIR / f"empty_{mode_name}.png"
        view_empty.grab().save(str(p_empty))
        print(f"Saved: {p_empty}")
        view_empty.close()

        # 2. Active Conversation
        view_conv = AIChatView(db=db)
        if active_proj:
            view_conv.set_active_project(active_proj)
            view_conv.set_current_workspace("Assessment")
        view_conv.resize(460, 780)
        view_conv.show()
        view_conv._append_message("user", SAMPLE_PROMPT)
        view_conv._append_message("assistant", SAMPLE_REPLY, "builtin_offline")
        cmds = view_conv.extract_shell_commands(SAMPLE_REPLY)
        view_conv._update_commands_shelf(cmds)
        app.processEvents()

        p_conv = OUTPUT_DIR / f"active_conversation_{mode_name}.png"
        view_conv.grab().save(str(p_conv))
        print(f"Saved: {p_conv}")
        view_conv.close()

        # 3. Generation in Progress
        view_prog = AIChatView(db=db)
        if active_proj:
            view_prog.set_active_project(active_proj)
        view_prog.resize(460, 780)
        view_prog.show()
        view_prog._append_message("user", "Explain SQLMap tamper scripts for WAF evasion")
        view_prog.btn_send.setEnabled(False)
        view_prog.btn_stop.setEnabled(True)
        view_prog.input_edit.setEnabled(False)
        view_prog.lbl_loading.setText("⏳ AI Assistant is thinking...")
        app.processEvents()

        p_prog = OUTPUT_DIR / f"generation_in_progress_{mode_name}.png"
        view_prog.grab().save(str(p_prog))
        print(f"Saved: {p_prog}")
        view_prog.close()

        # 4. Generation Stopped
        view_stop = AIChatView(db=db)
        if active_proj:
            view_stop.set_active_project(active_proj)
        view_stop.resize(460, 780)
        view_stop.show()
        view_stop._append_message("user", "Explain SQLMap tamper scripts for WAF evasion")
        view_stop._append_message("assistant", "*[Generation stopped by operator]*", "stopped")
        view_stop.btn_send.setEnabled(True)
        view_stop.btn_stop.setEnabled(False)
        view_stop.input_edit.setEnabled(True)
        view_stop.lbl_loading.setText("Generation stopped by operator.")
        app.processEvents()

        p_stop = OUTPUT_DIR / f"generation_stopped_{mode_name}.png"
        view_stop.grab().save(str(p_stop))
        print(f"Saved: {p_stop}")
        view_stop.close()


if __name__ == "__main__":
    capture_all()

