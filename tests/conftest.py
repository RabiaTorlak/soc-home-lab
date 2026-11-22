import os
import sys

# soar/ dizinini import yoluna ekle ki testler modülleri doğrudan import edebilsin
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "soar"))
