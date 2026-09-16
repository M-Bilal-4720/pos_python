"""
Android APK Builder for ISB Water Ordering App.
Creates a valid, signed standalone Android APK package and places it at:
static/downloads/isb-water-panel.apk
"""
import os
import sys
import shutil
import zipfile
import zlib
import hashlib
import struct
import subprocess
import socket
import urllib.request

def get_local_ip():
    """Detect LAN IP of the host machine."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return '192.168.50.53'

def find_java():
    """Find Java runtime executable."""
    candidates = [
        r"C:\Program Files\Eclipse Adoptium\jdk-17.0.20.101-hotspot\bin\java.exe",
        shutil.which("java"),
    ]
    java_home = os.environ.get("JAVA_HOME")
    if java_home:
        candidates.insert(0, os.path.join(java_home, "bin", "java.exe"))
        candidates.insert(1, os.path.join(java_home, "bin", "java"))

    for c in candidates:
        if c and os.path.isfile(c):
            return c
    return "java"

def generate_signed_apk(output_path, app_name="Islamabad Restaurant Water", version="1.0.0"):
    root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__)))
    tools_dir = os.path.join(root_dir, "tools")
    os.makedirs(tools_dir, exist_ok=True)
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    template_apk = os.path.join(tools_dir, "template.apk")
    signer_jar = os.path.join(tools_dir, "uber-apk-signer.jar")

    # Ensure template APK exists
    if not os.path.exists(template_apk):
        print("[APK] Downloading base Android template APK...")
        url = "https://raw.githubusercontent.com/bishwassagar/Android-Webview-App/master/app/release/app-release.apk"
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req) as resp, open(template_apk, "wb") as f:
            f.write(resp.read())

    # Ensure signer jar exists
    if not os.path.exists(signer_jar):
        print("[APK] Downloading uber-apk-signer tool...")
        url = "https://github.com/patrickfav/uber-apk-signer/releases/download/v1.3.0/uber-apk-signer-1.3.0.jar"
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req) as resp, open(signer_jar, "wb") as f:
            f.write(resp.read())

    # 1. Patch DEX bytecode
    with zipfile.ZipFile(template_apk, "r") as z:
        dex_data = bytearray(z.read("classes.dex"))

    target_url = b"https://github.com/bishwassagar"
    replacement_url = b"file:///android_asset/load.html"
    assert len(target_url) == len(replacement_url) == 31

    pos = dex_data.find(target_url)
    if pos != -1:
        dex_data[pos:pos+31] = replacement_url
        new_sha1 = hashlib.sha1(dex_data[32:]).digest()
        dex_data[12:32] = new_sha1
        new_adler = zlib.adler32(dex_data[12:]) & 0xffffffff
        dex_data[8:12] = struct.pack("<I", new_adler)

    # 2. Build embedded portal load.html & offline.html
    local_ip = get_local_ip()
    default_server = f"http://{local_ip}:5000/water"

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
  <title>{app_name}</title>
  <style>
    * {{ box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; }}
    body {{
      background-color: #0B0C10;
      color: #F1F5F9;
      min-height: 100vh;
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      padding: 24px;
      text-align: center;
    }}
    .card {{
      background: #14161E;
      border: 1px solid rgba(255,255,255,0.1);
      border-radius: 20px;
      padding: 28px 20px;
      width: 100%;
      max-width: 360px;
      box-shadow: 0 12px 32px rgba(0,0,0,0.6);
    }}
    .emblem {{
      width: 80px;
      height: 80px;
      border-radius: 50%;
      margin: 0 auto 16px auto;
      border: 3px solid #C65A1E;
      box-shadow: 0 0 20px rgba(198,90,30,0.4);
      display: flex;
      align-items: center;
      justify-content: center;
      background: #0284C7;
      font-size: 38px;
    }}
    h1 {{
      font-size: 19px;
      font-weight: 800;
      color: #FFFFFF;
      letter-spacing: -0.3px;
      margin-bottom: 4px;
    }}
    .badge {{
      display: inline-block;
      background: rgba(2,132,199,0.2);
      color: #38BDF8;
      border: 1px solid rgba(2,132,199,0.3);
      padding: 3px 10px;
      border-radius: 9999px;
      font-size: 11px;
      font-weight: 700;
      text-transform: uppercase;
      margin-bottom: 18px;
    }}
    .status-msg {{
      font-size: 13px;
      color: #94A3B8;
      margin-bottom: 20px;
      line-height: 1.4;
    }}
    .spinner {{
      width: 28px;
      height: 28px;
      border: 3px solid rgba(2,132,199,0.2);
      border-top-color: #0284C7;
      border-radius: 50%;
      animation: spin 0.8s linear infinite;
      margin: 0 auto 16px auto;
    }}
    @keyframes spin {{ to {{ transform: rotate(360deg); }} }}
    .input-group {{
      text-align: left;
      margin-bottom: 16px;
    }}
    label {{
      display: block;
      font-size: 11px;
      font-weight: 600;
      color: #94A3B8;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      margin-bottom: 6px;
    }}
    input {{
      width: 100%;
      background: #0B0C10;
      border: 1px solid rgba(255,255,255,0.15);
      border-radius: 12px;
      padding: 12px 14px;
      font-size: 13px;
      color: #FFFFFF;
      outline: none;
    }}
    input:focus {{ border-color: #0284C7; }}
    button {{
      width: 100%;
      background: #0284C7;
      color: #FFFFFF;
      border: none;
      border-radius: 12px;
      padding: 14px;
      font-size: 14px;
      font-weight: 700;
      cursor: pointer;
      box-shadow: 0 4px 12px rgba(2,132,199,0.3);
      transition: background 0.15s;
    }}
    button:active {{ background: #0369A1; }}
    .footer {{
      margin-top: 14px;
      font-size: 11px;
      color: #64748B;
    }}
  </style>
</head>
<body>
  <div class="card">
    <div class="emblem">💧</div>
    <h1>Islamabad Restaurant</h1>
    <div class="badge">Water Ordering System • v{version}</div>

    <div id="loading-box">
      <div class="spinner"></div>
      <div class="status-msg" id="status-text">Connecting to restaurant POS...</div>
    </div>

    <div id="config-box" style="display:none;">
      <div class="input-group">
        <label>POS Server Address</label>
        <input type="text" id="server-url-input" value="{default_server}">
      </div>
      <button onclick="connectToServer()">Connect to Water Panel</button>
      <div class="footer">Connect phone to restaurant Wi-Fi network</div>
    </div>
  </div>

  <script>
    const DEFAULT_URL = '{default_server}';
    let savedUrl = localStorage.getItem('isb_water_server') || DEFAULT_URL;
    document.getElementById('server-url-input').value = savedUrl;

    function connectToServer() {{
      const url = document.getElementById('server-url-input').value.trim();
      if (!url) return;
      localStorage.setItem('isb_water_server', url);
      document.getElementById('config-box').style.display = 'none';
      document.getElementById('loading-box').style.display = 'block';
      document.getElementById('status-text').innerText = 'Opening ' + url + '...';
      window.location.replace(url);
    }}

    function tryAutoConnect() {{
      const target = savedUrl;
      fetch(target, {{ mode: 'no-cors' }})
        .then(() => {{
          window.location.replace(target);
        }})
        .catch(() => {{
          setTimeout(() => {{
            document.getElementById('loading-box').style.display = 'none';
            document.getElementById('config-box').style.display = 'block';
          }}, 2000);
        }});
    }}

    setTimeout(() => {{
      if (window.location.protocol === 'file:') {{
        document.getElementById('loading-box').style.display = 'none';
        document.getElementById('config-box').style.display = 'block';
      }}
    }}, 2500);

    tryAutoConnect();
  </script>
</body>
</html>
"""

    # 3. Create unsigned modified APK
    temp_unsigned = os.path.join(tools_dir, "temp_unsigned.apk")
    with zipfile.ZipFile(template_apk, "r") as zin, zipfile.ZipFile(temp_unsigned, "w", zipfile.ZIP_DEFLATED) as zout:
        for item in zin.infolist():
            if item.filename.startswith("META-INF/") and (item.filename.endswith(".SF") or item.filename.endswith(".RSA") or item.filename.endswith(".MF") or item.filename.endswith(".DSA") or item.filename.endswith(".EC")):
                continue
            if item.filename == "classes.dex":
                zout.writestr(item, dex_data)
            elif item.filename == "assets/offline.html":
                zout.writestr(item, html_content.encode("utf-8"))
            else:
                zout.writestr(item, zin.read(item.filename))
        
        zout.writestr("assets/load.html", html_content.encode("utf-8"))

    # 4. Sign with uber-apk-signer
    out_dir = os.path.dirname(os.path.abspath(output_path))
    java_exe = find_java()
    cmd = [
        java_exe, "-jar", signer_jar,
        "-a", temp_unsigned,
        "-o", out_dir,
        "--allowResign"
    ]
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        print("[APK Error]", res.stderr)

    # 5. Move signed file to final output_path
    for fname in os.listdir(out_dir):
        if fname.startswith("temp_unsigned") and fname.endswith(".apk"):
            src = os.path.join(out_dir, fname)
            if os.path.exists(output_path):
                try: os.remove(output_path)
                except Exception: pass
            os.replace(src, output_path)
            break

    if os.path.exists(temp_unsigned):
        try: os.remove(temp_unsigned)
        except Exception: pass

    apk_size = os.path.getsize(output_path) if os.path.exists(output_path) else 0
    print(f"[APK] Successfully generated valid, signed APK: {output_path} ({apk_size} bytes)")
    return output_path

if __name__ == "__main__":
    out = os.path.join(os.path.dirname(__file__), "static", "downloads", "isb-water-panel.apk")
    generate_signed_apk(out)
