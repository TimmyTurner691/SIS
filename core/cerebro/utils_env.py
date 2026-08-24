import os

def get_env_int(key, default):
    val = os.getenv(key)
    if val is None or str(val).strip() == "":
        return int(default)
    try:
        return int(val)
    except ValueError:
        print(f"⚠️ [ENV] Valor inválido para {key}='{val}', usando default {default}", flush=True)
        return int(default)

def get_env_bool(key, default):
    val = os.getenv(key)
    if val is None or str(val).strip() == "":
        return default
    return str(val).lower() == "true"

def get_env_float(key, default):
    val = os.getenv(key)
    if val is None or str(val).strip() == "":
        return float(default)
    try:
        return float(val)
    except ValueError:
        print(f"⚠️ [ENV] Valor inválido para {key}='{val}', usando default {default}", flush=True)
        return float(default)
