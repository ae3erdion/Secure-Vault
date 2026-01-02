import threading

class SecureClipboard:
    def __init__(self, root, clear_after=15):
        self.root = root
        self.clear_after = clear_after
        self.timer = None

    def copy(self, text):
        self.cancel()
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        self.root.update()

        self.timer = threading.Timer(self.clear_after, self.clear)
        self.timer.daemon = True
        self.timer.start()

    def clear(self):
        try:
            self.root.clipboard_clear()
        except Exception:
            pass

    def cancel(self):
        if self.timer:
            self.timer.cancel()
            self.timer = None
