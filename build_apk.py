"""
Native Android APK Builder for ISB Water Ordering App.
Compiles native resources with Google AAPT2, compiles Java bytecode with javac,
generates Dalvik DEX bytecode with D8, and signs with v1/v2/v3 signature schemes.
Output: static/downloads/isb-water-panel.apk
"""
import os
import shutil
import subprocess
from PIL import Image

def find_java():
    """Find Java runtime and compiler executables."""
    candidates = [
        r"C:\Program Files\Eclipse Adoptium\jdk-17.0.20.101-hotspot\bin",
    ]
    java_home = os.environ.get("JAVA_HOME")
    if java_home:
        candidates.insert(0, os.path.join(java_home, "bin"))

    for c in candidates:
        javac = os.path.join(c, "javac.exe" if os.name == "nt" else "javac")
        java = os.path.join(c, "java.exe" if os.name == "nt" else "java")
        if os.path.isfile(javac) and os.path.isfile(java):
            return javac, java

    return shutil.which("javac") or "javac", shutil.which("java") or "java"

def generate_signed_apk(output_path, app_name="ISB Water", version="1.1.1", version_code=3):
    root = os.path.abspath(os.path.dirname(__file__))
    tools_dir = os.path.join(root, "tools")
    app_dir = os.path.join(root, "android_app", "app", "src", "main")
    build_dir = os.path.join(root, "android_app", "build_tmp")

    if os.path.exists(build_dir):
        shutil.rmtree(build_dir, ignore_errors=True)
    os.makedirs(build_dir, exist_ok=True)
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    JAVAC, JAVA = find_java()
    AAPT2 = os.path.join(tools_dir, "aapt2.exe" if os.name == "nt" else "aapt2")
    ANDROID_JAR = os.path.join(tools_dir, "android.jar")
    R8_JAR = os.path.join(tools_dir, "r8.jar")
    SIGNER_JAR = os.path.join(tools_dir, "uber-apk-signer.jar")

    default_url = os.environ.get("SERVER_URL", "https://isbrestaurant.com/water")
    print(f"[APK BUILD] Target server: {default_url} | App Name: {app_name}")

    # 1. Prepare Launcher Icons from static/isb_qr_emblem.png
    logo_src = os.path.join(root, "static", "isb_qr_emblem.png")
    res_dir = os.path.join(app_dir, "res")

    icon_sizes = {
        "mipmap-mdpi": 48,
        "mipmap-hdpi": 72,
        "mipmap-xhdpi": 96,
        "mipmap-xxhdpi": 144,
        "mipmap-xxxhdpi": 192,
        "drawable": 96,
    }

    if os.path.exists(logo_src):
        img = Image.open(logo_src).convert("RGBA")
        for folder, size in icon_sizes.items():
            folder_path = os.path.join(res_dir, folder)
            os.makedirs(folder_path, exist_ok=True)
            resized = img.resize((size, size), Image.Resampling.LANCZOS)
            resized.save(os.path.join(folder_path, "ic_launcher.png"), "PNG")
            resized.save(os.path.join(folder_path, "ic_launcher_round.png"), "PNG")

    # 2. Update strings.xml
    strings_xml = f"""<?xml version="1.0" encoding="utf-8"?>
<resources>
    <string name="app_name">{app_name}</string>
    <string name="app_full_name">Islamabad Restaurant Water</string>
    <string name="default_server_url">{default_url}</string>
</resources>
"""
    with open(os.path.join(res_dir, "values", "strings.xml"), "w", encoding="utf-8") as f:
        f.write(strings_xml)

    # 3. Update AndroidManifest.xml
    manifest_xml = f"""<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.isb.water"
    android:versionCode="{version_code}"
    android:versionName="{version}">

    <uses-sdk
        android:minSdkVersion="21"
        android:targetSdkVersion="33" />

    <supports-screens
        android:anyDensity="true"
        android:smallScreens="true"
        android:normalScreens="true"
        android:largeScreens="true"
        android:xlargeScreens="true"
        android:resizeable="true" />

    <uses-permission android:name="android.permission.INTERNET" />
    <uses-permission android:name="android.permission.ACCESS_NETWORK_STATE" />
    <uses-permission android:name="android.permission.ACCESS_WIFI_STATE" />

    <application
        android:allowBackup="true"
        android:icon="@mipmap/ic_launcher"
        android:label="@string/app_name"
        android:roundIcon="@mipmap/ic_launcher"
        android:supportsRtl="true"
        android:usesCleartextTraffic="true"
        android:theme="@android:style/Theme.NoTitleBar">
        
        <activity
            android:name=".MainActivity"
            android:exported="true"
            android:configChanges="orientation|keyboardHidden|screenSize"
            android:windowSoftInputMode="adjustResize"
            android:theme="@android:style/Theme.NoTitleBar">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
    </application>
</manifest>
"""
    with open(os.path.join(app_dir, "AndroidManifest.xml"), "w", encoding="utf-8") as f:
        f.write(manifest_xml)

    # 4. Step 1: AAPT2 Compile Resources
    compiled_res = os.path.join(build_dir, "compiled_res.zip")
    subprocess.run([AAPT2, "compile", "--dir", res_dir, "-o", compiled_res], check=True)

    # 5. Step 2: AAPT2 Link Resources
    unaligned_apk = os.path.join(build_dir, "unaligned.apk")
    gen_dir = os.path.join(build_dir, "gen")
    os.makedirs(gen_dir, exist_ok=True)
    manifest_path = os.path.join(app_dir, "AndroidManifest.xml")

    subprocess.run([
        AAPT2, "link",
        "-I", ANDROID_JAR,
        "--manifest", manifest_path,
        "-o", unaligned_apk,
        "--java", gen_dir,
        "--auto-add-overlay",
        compiled_res
    ], check=True)

    # 6. Step 3: Javac Compile Java Sources
    classes_dir = os.path.join(build_dir, "classes")
    os.makedirs(classes_dir, exist_ok=True)
    r_java = os.path.join(gen_dir, "com", "isb", "water", "R.java")
    java_file = os.path.join(app_dir, "java", "com", "isb", "water", "MainActivity.java")

    subprocess.run([
        JAVAC,
        "-classpath", ANDROID_JAR,
        "-d", classes_dir,
        "-source", "1.8",
        "-target", "1.8",
        r_java,
        java_file
    ], check=True)

    # 7. Step 4: D8 Compile bytecode to classes.dex
    class_files = []
    for root_c, _, files in os.walk(classes_dir):
        for f in files:
            if f.endswith(".class"):
                class_files.append(os.path.join(root_c, f))

    dex_dir = os.path.join(build_dir, "dex")
    os.makedirs(dex_dir, exist_ok=True)

    subprocess.run([
        JAVA, "-cp", R8_JAR,
        "com.android.tools.r8.D8",
        "--output", dex_dir,
        "--lib", ANDROID_JAR,
        "--min-api", "21"
    ] + class_files, check=True)

    # Add classes.dex into unaligned_apk
    dex_path = os.path.join(dex_dir, "classes.dex")
    import zipfile
    with zipfile.ZipFile(unaligned_apk, "a") as z:
        z.write(dex_path, "classes.dex")

    # 8. Step 5: Sign with uber-apk-signer (Zipalign + v1 + v2 + v3)
    out_dir = os.path.dirname(os.path.abspath(output_path))
    subprocess.run([
        JAVA, "-jar", SIGNER_JAR,
        "-a", unaligned_apk,
        "-o", out_dir,
        "--allowResign"
    ], check=True)

    # Rename to output_path
    for fname in os.listdir(out_dir):
        if fname.startswith("unaligned") and fname.endswith(".apk"):
            src = os.path.join(out_dir, fname)
            if os.path.exists(output_path):
                try: os.remove(output_path)
                except Exception: pass
            os.rename(src, output_path)
            break

    shutil.rmtree(build_dir, ignore_errors=True)
    apk_size = os.path.getsize(output_path) if os.path.exists(output_path) else 0
    print(f"[APK COMPLETE] Successfully generated native signed APK: {output_path} ({apk_size} bytes)")
    return output_path

if __name__ == "__main__":
    out = os.path.join(os.path.dirname(__file__), "static", "downloads", "isb-water-panel.apk")
    generate_signed_apk(out)
