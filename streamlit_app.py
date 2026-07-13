# Streamlit Cloud entry point
# Loads and runs the main app from app/app.py

import importlib.util
import os

app_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "app", "app.py")
spec = importlib.util.spec_from_file_location("app_main", app_path)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
