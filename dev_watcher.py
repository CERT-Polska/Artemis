from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from pathlib import Path
import subprocess
import time

ROOT = Path(__file__).parent
MODULES_DIR = ROOT / "artemis" / "modules"


class Handler(FileSystemEventHandler):
    last = 0

    def on_modified(self, event):
        if not event.src_path.endswith(".py"):
            return

        now = time.time()
        if now - self.last < 0.5:
            return
        self.last = now

        mod = Path(event.src_path).stem
        service = f"karton-{mod}"

        print(f"[dev-watcher] restart {service}")
        subprocess.run(
            ["docker", "compose", "restart", service],
            stdout=subprocess.STDOUT,
            stderr=subprocess.DEVNULL,
        )


observer = Observer()
observer.schedule(Handler(), MODULES_DIR, recursive=True)
observer.start()

print("[dev-watcher] watching artemis/modules")

try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    observer.stop()

observer.join()
