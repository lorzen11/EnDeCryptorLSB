import sys
import os
import struct
import base64
import hashlib
import hmac
from pathlib import Path
from PIL import Image
from PyQt5 import QtWidgets, QtGui, QtCore
import secrets

class HMACCounterRNG:
    def __init__(self, key: bytes):
        self.key = key
        self.counter = 0
        self._buf = b""
        self._buf_pos = 0

    def _refill(self):
        ctr_bytes = self.counter.to_bytes(16, "big")
        h = hmac.new(self.key, ctr_bytes, hashlib.sha256).digest()
        self._buf = h
        self._buf_pos = 0
        self.counter += 1

    def get_bytes(self, n):
        out = bytearray()
        while n > 0:
            if self._buf_pos >= len(self._buf):
                self._refill()
            take = min(n, len(self._buf) - self._buf_pos)
            out += self._buf[self._buf_pos:self._buf_pos+take]
            self._buf_pos += take
            n -= take
        return bytes(out)

    def randbelow(self, n):
        if n <= 0:
            raise ValueError("n must be positive")

        while True:
            b = int.from_bytes(self.get_bytes(8), "big")
            if b < (1 << 64) - ((1 << 64) % n):
                return b % n

def derive_key_from_text(user_key: str, salt: bytes = b"stegosalt", rounds: int = 100000):
    if user_key is None:
        user_key = ""
    return hashlib.pbkdf2_hmac("sha256", user_key.encode("utf-8"), salt, rounds, dklen=32)


def image_to_bytes_and_mode(img: Image.Image):
    mode = img.mode
    if mode not in ("RGB", "RGBA"):
        img = img.convert("RGBA")
        mode = "RGBA"
    data = bytearray(img.tobytes())
    w, h = img.size
    channels = 3 if mode == "RGB" else 4
    return data, mode, (w, h), channels

def bytes_to_image(data: bytes, mode: str, size):
    return Image.frombytes(mode, size, bytes(data))

def capacity_bits(size, channels):
    w, h = size
    return w * h * channels

def embed_message_into_image(img: Image.Image, message_bytes: bytes, user_key: str):

    data, mode, size, channels = image_to_bytes_and_mode(img)
    cap = capacity_bits(size, channels)
    msglen_bits = len(message_bytes) * 8
    if msglen_bits > cap:
        raise ValueError(f"Image capacity insufficient: required {msglen_bits} bits, available {cap} bits.")

    key = derive_key_from_text(user_key)
    rng = HMACCounterRNG(key)

    n_positions = cap
    indices = list(range(n_positions))
    for i in range(n_positions - 1, 0, -1):
        j = rng.randbelow(i + 1)
        indices[i], indices[j] = indices[j], indices[i]

    bits = []
    for byte in message_bytes:
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)

    for k, bit in enumerate(bits):
        pos = indices[k]  
        data[pos] = (data[pos] & 0xFE) | bit

    out_img = bytes_to_image(bytes(data), mode, size)
    return out_img

def extract_message_from_image(img: Image.Image, user_key: str):

    data, mode, size, channels = image_to_bytes_and_mode(img)
    cap = capacity_bits(size, channels)

    key = derive_key_from_text(user_key)
    rng = HMACCounterRNG(key)

    n_positions = cap
    indices = list(range(n_positions))
    for i in range(n_positions - 1, 0, -1):
        j = rng.randbelow(i + 1)
        indices[i], indices[j] = indices[j], indices[i]

    if cap < 32:
        raise ValueError("Image too small to store message length.")

    length_bits = []
    for k in range(32):
        pos = indices[k]
        length_bits.append(data[pos] & 1)

    length_bytes = bytearray()
    for i in range(0, 32, 8):
        b = 0
        for j in range(8):
            b = (b << 1) | length_bits[i + j]
        length_bytes.append(b)
    msg_len = struct.unpack(">I", bytes(length_bytes))[0]

    total_needed_bits = 32 + msg_len * 8
    if total_needed_bits > cap:
        raise ValueError(f"Required length {msg_len} bytes exceeds image capacity ({cap} bits).")

    bits = []
    for k in range(32, 32 + msg_len * 8):
        pos = indices[k]
        bits.append(data[pos] & 1)

    msg_bytes = bytearray()
    for i in range(0, len(bits), 8):
        b = 0
        for j in range(8):
            b = (b << 1) | bits[i + j]
        msg_bytes.append(b)

    return bytes(msg_bytes)

# --------------------
# GUI
# --------------------
def resource_path(relative_path):
    try:
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")

    return os.path.join(base_path, relative_path)

class StegoWindow(QtWidgets.QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("EnDeCryptorLSB")
        self.setWindowIcon(QtGui.QIcon(resource_path("icon.ico")))
        self.setFixedSize(400, 180)
        self.setWindowFlags(QtCore.Qt.FramelessWindowHint)
        self.setAttribute(QtCore.Qt.WA_TranslucentBackground)
        self.background_image = QtGui.QPixmap(resource_path("background.png"))
        self._build_ui()

    def paintEvent(self, event):
        painter = QtGui.QPainter(self)
        
        scaled_pixmap = self.background_image.scaled(
            self.size(), 
            QtCore.Qt.IgnoreAspectRatio, 
            QtCore.Qt.SmoothTransformation
        )
        
        painter.drawPixmap(self.rect(), scaled_pixmap)


    def _build_ui(self):
        self.title_bar = self._create_title_bar()
        self.title_bar.setParent(self)
        self.title_bar.setGeometry(0, 0, 400, 30)
        
        self.mode = 0  # 0 - encrypt, 1 - decrypt

        # Mode
        self.btn_modeChanger = QtWidgets.QPushButton("Encrypt", self)
        self.btn_modeChanger.setGeometry(10, 40, 100, 25)

        # File selection
        self.file_path = QtWidgets.QLineEdit(self)
        self.file_path.setPlaceholderText("Image Path")
        self.file_path.setReadOnly(True)
        self.file_path.setGeometry(10, 70, 288, 25)

        self.btn_browse = QtWidgets.QPushButton("Browse", self)
        self.btn_browse.setGeometry(300, 70, 90, 25)
        self.setAcceptDrops(True)

        # For encryption: text input
        self.text_edit = QtWidgets.QPlainTextEdit(self)
        self.text_edit.setPlaceholderText("Encrypt text in image")
        self.text_edit.setGeometry(10, 100, 380, 40)

        # Key input and generate
        self.key_edit = QtWidgets.QLineEdit(self)
        self.key_edit.setPlaceholderText("Enter Key")
        self.key_edit.setGeometry(10, 144, 260, 25)
        
        self.btn_gen_key = QtWidgets.QPushButton("Generate Key", self)
        self.btn_gen_key.setGeometry(273, 144, 80, 25)

        # Run button
        self.btn_run = QtWidgets.QPushButton("Run", self)
        self.btn_run.setGeometry(352, 144, 40, 25)

        # Connections
        self.btn_modeChanger.clicked.connect(self.modeChanger)
        self.btn_browse.clicked.connect(self.choose_file)
        self.btn_gen_key.clicked.connect(self.generate_key)
        self.btn_run.clicked.connect(self.run_action)

    def clearMode(self):
        self.file_path.clear()
        self.text_edit.clear()
        self.key_edit.clear()

    def modeChanger(self):
        self.modeWidgetPositionChanger()
        if self.mode == 0:
            self.mode = 1
            self.btn_modeChanger.setText("Decrypt")
            self.clearMode()
            self.text_edit.hide()
            self.text_edit.setEnabled(False)
            self.btn_gen_key.hide()
            self.btn_gen_key.setEnabled(False)
        else:
            self.mode = 0
            self.btn_modeChanger.setText("Encrypt")
            self.clearMode()
            self.text_edit.show()
            self.text_edit.setEnabled(True)
            self.btn_gen_key.show()
            self.btn_gen_key.setEnabled(True)

    def modeWidgetPositionChanger(self):
        if self.mode == 0:
            self.key_edit.setGeometry(10, 100, 288, 25)
            self.btn_run.setGeometry(300, 100, 90, 25)
        else:
            self.key_edit.setGeometry(10, 144, 260, 25)
            self.btn_run.setGeometry(352, 144, 40, 25)

    def choose_file(self, event=None):
        if hasattr(event, 'mimeData') and event is not None:
            if event.mimeData().hasUrls():
                urls = event.mimeData().urls()
                if urls:
                    file_path = urls[0].toLocalFile()
                    if self.is_image_file(file_path):
                        self.process_selected_file(file_path)
                        event.acceptProposedAction()
            return

        path, _ = QtWidgets.QFileDialog.getOpenFileName(self, "Image Select", "", "Images (*.png *.jpg *.jpeg)")
        if path:
            self.process_selected_file(path)

    def process_selected_file(self, path):
        self.file_path.setText(path)

    def is_image_file(self, file_path):
        image_extensions = {'.png', '.jpg', '.jpeg'}
        return Path(file_path).suffix.lower() in image_extensions

    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            urls = event.mimeData().urls()
            if urls and self.is_image_file(urls[0].toLocalFile()):
                event.acceptProposedAction()

    def dragMoveEvent(self, event):
        if event.mimeData().hasUrls():
            urls = event.mimeData().urls()
            if urls and self.is_image_file(urls[0].toLocalFile()):
                event.acceptProposedAction()

    def dropEvent(self, event):
        self.choose_file(event)

    def run_action(self):
        if self.mode == 0:
            self.perform_encrypt()
        else:
            self.perform_decrypt()

    def generate_key(self):
        raw = secrets.token_bytes(18)
        key = base64.urlsafe_b64encode(raw).decode('ascii').rstrip("=")
        self.key_edit.setText(key)

    def perform_encrypt(self):
        path = self.file_path.text().strip()
        if not path or not os.path.exists(path):
            QtWidgets.QMessageBox.warning(self, "Error", "Select a valid image file.")
            return

        user_key = self.key_edit.text().strip()
        if not user_key:
            raw = secrets.token_bytes(18)
            user_key = base64.urlsafe_b64encode(raw).decode('ascii').rstrip("=")
            self.key_edit.setText(user_key)
            QtWidgets.QMessageBox.information(self, "Key Generated", f"Key automatically generated. Save it - decryption is impossible without it:\n\n{user_key}")

        text = self.text_edit.toPlainText()
        if not text:
            QtWidgets.QMessageBox.warning(self, "Error", "Enter text to encrypt.")
            return
        
        message_utf8 = text.encode("utf-8")

        length_prefix = struct.pack(">I", len(message_utf8))
        payload = length_prefix + message_utf8

        try:
            img = Image.open(path)
            if img.format and img.format.upper() in ("JPEG", "JPG"):
                QtWidgets.QMessageBox.information(self, "JPG Input", "Input file is JPEG - stego will be saved as PNG since JPEG compression would lose data.")
            _, _, size, channels = image_to_bytes_and_mode(img)
            cap = capacity_bits(size, channels)
            needed = len(payload) * 8
            if needed > cap:
                QtWidgets.QMessageBox.critical(self, "Insufficient Space", f"Image too small: required {needed} bits (~{needed//8} bytes), available {cap} bits (~{cap//8} bytes).")
                return
            
            out_path, _ = QtWidgets.QFileDialog.getSaveFileName(self, "Save as", "", "PNG Image (*.png)")
            if out_path:
                if not out_path.lower().endswith(".png"):
                    out_path += ".png"

            out_img = embed_message_into_image(img, payload, user_key)
            out_img.save(out_path, "PNG")
            QtWidgets.QMessageBox.information(self, "Encryption Complete", 
                f"Message successfully hidden in image!\n\n"
                f"Saved file: {out_path}\n"
                f"Message length: {len(message_utf8)} bytes\n"
                f"Key: {user_key}\n\n"
                f"(Save the key - it's required for decryption.)")
        except Exception as e:
            QtWidgets.QMessageBox.critical(self, "Error", f"Error during encryption:\n{e}")

    def perform_decrypt(self):
        path = self.file_path.text().strip()
        if not path or not os.path.exists(path):
            QtWidgets.QMessageBox.warning(self, "Error", "Select a valid image file.")
            return

        user_key = self.key_edit.text().strip()
        if not user_key:
            QtWidgets.QMessageBox.warning(self, "Error", "Enter key - decryption is impossible without it.")
            return

        try:
            img = Image.open(path)
            msg_bytes = extract_message_from_image(img, user_key)
            try:
                txt = msg_bytes.decode("utf-8")
                QtWidgets.QMessageBox.information(self, "Decryption Complete", 
                    f"Message successfully extracted!\n\n"
                    f"Text:\n{txt}")
            except UnicodeDecodeError:
                QtWidgets.QMessageBox.information(self, "Decryption Complete", 
                    f"Data successfully extracted!\n\n"
                    f"(Data is not in UTF-8 format)\n"
                    f"Hex representation:\n{msg_bytes.hex()}")
        except Exception as e:
            QtWidgets.QMessageBox.critical(self, "Error", f"Error during decryption:\n{e}")

    def _create_title_bar(self):
        title_widget = QtWidgets.QWidget(self) 
        title_widget.setFixedHeight(30)
        title_widget.setGeometry(0, 0, 400, 30)

        title_label = QtWidgets.QLabel("EnDeCryptorLSB", title_widget)
        title_label.setGeometry(10, 5, 100, 30)
        title_label.setStyleSheet("color: white; font-weight: bold;")
        
        min_btn = QtWidgets.QPushButton(title_widget)
        close_btn = QtWidgets.QPushButton(title_widget)

        min_btn.setGeometry(335, 10, 23, 23)
        close_btn.setGeometry(365, 10, 23, 23)
        
        btn_style = """
            QPushButton {
                background: transparent;
                color: white;
                border: none;
                font-size: 16px;
                font-weight: bold;
                padding: 0px 8px;
            }
            QPushButton:hover {
                background: rgba(255,255,255,30);
            }
            QPushButton:pressed {
                background: rgba(255,255,255,50);
            }w
        """
        
        min_btn.setStyleSheet(btn_style)
        close_btn.setStyleSheet(btn_style + "QPushButton:hover { background: #e81123; }")
        min_btn.setIcon(QtGui.QIcon(resource_path("min.png")))
        close_btn.setIcon(QtGui.QIcon(resource_path("close.png")))
        min_btn.setIconSize(QtCore.QSize(23, 23))
        close_btn.setIconSize(QtCore.QSize(23, 23))

        min_btn.clicked.connect(self.showMinimized)
        close_btn.clicked.connect(self.close)
        
        return title_widget
    
    def mousePressEvent(self, event):
        if event.button() == QtCore.Qt.LeftButton:
            self.drag_start_position = event.globalPos() - self.frameGeometry().topLeft()
            event.accept()
    
    def mouseMoveEvent(self, event):
        if event.buttons() == QtCore.Qt.LeftButton and hasattr(self, 'drag_start_position'):
            self.move(event.globalPos() - self.drag_start_position)
            event.accept()


def main():    
    app = QtWidgets.QApplication(sys.argv)
    w = StegoWindow()
    w.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()       