package com.isb.water;

import android.annotation.SuppressLint;
import android.app.Activity;
import android.content.Context;
import android.content.SharedPreferences;
import android.graphics.Color;
import android.os.Bundle;
import android.view.KeyEvent;
import android.view.View;
import android.view.ViewGroup;
import android.webkit.CookieManager;
import android.webkit.JavascriptInterface;
import android.webkit.WebChromeClient;
import android.webkit.WebResourceError;
import android.webkit.WebResourceRequest;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.FrameLayout;
import android.widget.ProgressBar;
import android.widget.Toast;

public class MainActivity extends Activity {

    private static final String PREFS_NAME = "isb_water_prefs";
    private static final String KEY_SERVER_URL = "server_url";

    private WebView webView;
    private ProgressBar progressBar;
    private SharedPreferences prefs;

    @SuppressLint("SetJavaScriptEnabled")
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        prefs = getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
        String defaultUrl = getString(R.string.default_server_url);
        String lastBuiltUrl = prefs.getString("last_built_url", "");
        String serverUrl;
        if (!defaultUrl.equals(lastBuiltUrl) || defaultUrl.contains("192.168.50.53")) {
            serverUrl = defaultUrl;
            prefs.edit().putString(KEY_SERVER_URL, defaultUrl)
                        .putString("last_built_url", defaultUrl)
                        .apply();
        } else {
            serverUrl = prefs.getString(KEY_SERVER_URL, defaultUrl);
        }

        FrameLayout root = new FrameLayout(this);
        root.setBackgroundColor(Color.parseColor("#0B0C10"));

        webView = new WebView(this);
        webView.setBackgroundColor(Color.parseColor("#0B0C10"));

        progressBar = new ProgressBar(this, null, android.R.attr.progressBarStyleHorizontal);
        progressBar.setMax(100);
        progressBar.setLayoutParams(new FrameLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, 8
        ));
        progressBar.setVisibility(View.GONE);

        root.addView(webView, new FrameLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT
        ));
        root.addView(progressBar);
        setContentView(root);

        WebSettings ws = webView.getSettings();
        ws.setJavaScriptEnabled(true);
        ws.setDomStorageEnabled(true);
        ws.setDatabaseEnabled(true);
        ws.setAllowFileAccess(true);
        ws.setAllowContentAccess(true);
        ws.setUseWideViewPort(true);
        ws.setLoadWithOverviewMode(true);
        ws.setSupportZoom(false);
        ws.setBuiltInZoomControls(false);
        ws.setTextZoom(100);
        webView.clearCache(true);
        ws.setCacheMode(WebSettings.LOAD_NO_CACHE);

        CookieManager cookieManager = CookieManager.getInstance();
        cookieManager.setAcceptCookie(true);
        cookieManager.setAcceptThirdPartyCookies(webView, true);

        webView.addJavascriptInterface(new WebAppInterface(), "AndroidBridge");

        webView.setWebChromeClient(new WebChromeClient() {
            @Override
            public void onProgressChanged(WebView view, int newProgress) {
                if (newProgress < 100) {
                    progressBar.setVisibility(View.VISIBLE);
                    progressBar.setProgress(newProgress);
                } else {
                    progressBar.setVisibility(View.GONE);
                }
            }
        });

        webView.setWebViewClient(new WebViewClient() {
            @Override
            public boolean shouldOverrideUrlLoading(WebView view, WebResourceRequest request) {
                return false;
            }
            @Override
            public boolean shouldOverrideUrlLoading(WebView view, String url) {
                return false;
            }
            @Override
            public void onPageFinished(WebView view, String url) {
                super.onPageFinished(view, url);
                CookieManager.getInstance().flush();
            }
            @Override
            public void onReceivedError(WebView view, WebResourceRequest request, WebResourceError error) {
                if (request.isForMainFrame()) {
                    showOfflineErrorPage(view);
                }
            }
            @Override
            public void onReceivedError(WebView view, int errorCode, String description, String failingUrl) {
                showOfflineErrorPage(view);
            }
        });

        webView.loadUrl(serverUrl);
    }

    private void showOfflineErrorPage(WebView view) {
        String current = prefs.getString(KEY_SERVER_URL, getString(R.string.default_server_url));
        String html = "<!DOCTYPE html><html><head><meta name='viewport' content='width=device-width, initial-scale=1'>"
            + "<style>"
            + "body{background:#0B0C10;color:#F1F5F9;font-family:sans-serif;padding:30px 20px;text-align:center;box-sizing:border-box;margin:0;}"
            + ".icon{font-size:48px;margin-bottom:10px;}"
            + "h2{margin:0 0 10px 0;font-size:20px;font-weight:bold;color:#fff;}"
            + "p{color:#94A3B8;font-size:13px;line-height:1.5;margin:0 0 20px 0;}"
            + ".card{background:#14161E;border:1px solid rgba(255,255,255,0.1);border-radius:18px;padding:20px;text-align:left;}"
            + "label{display:block;font-size:11px;font-weight:bold;color:#38BDF8;text-transform:uppercase;margin-bottom:6px;}"
            + "input{width:100%;box-sizing:border-box;padding:14px;border-radius:12px;border:1px solid rgba(255,255,255,0.15);background:#0B0C10;color:#fff;font-size:15px;outline:none;margin-bottom:14px;}"
            + "button{width:100%;padding:14px;border-radius:12px;border:none;background:#0284C7;color:#fff;font-size:15px;font-weight:bold;cursor:pointer;}"
            + "</style></head><body>"
            + "<div class='icon'>📡</div>"
            + "<h2>Server Not Reachable</h2>"
            + "<p>Make sure this phone is on the same Wi-Fi network as the POS computer, then enter the current POS IP address:</p>"
            + "<div class='card'>"
            + "<label>Server URL / IP Address</label>"
            + "<input type='text' id='url' value='" + current + "' placeholder='http://192.168.50.52:5000/water'>"
            + "<button onclick='save()'>Connect Now</button>"
            + "</div>"
            + "<script>"
            + "function save(){"
            + "  var u=document.getElementById('url').value.trim();"
            + "  if(!u.startsWith('http://') && !u.startsWith('https://')) u='http://'+u;"
            + "  if(!u.includes(':5000')) u=u+':5000';"
            + "  if(!u.endsWith('/water')) u=u+'/water';"
            + "  if(window.AndroidBridge) window.AndroidBridge.setServerUrl(u);"
            + "  else location.href=u;"
            + "}"
            + "</script>"
            + "</body></html>";
        view.loadDataWithBaseURL(null, html, "text/html", "UTF-8", null);
    }

    private class WebAppInterface {
        @JavascriptInterface
        public void setServerUrl(final String newUrl) {
            runOnUiThread(new Runnable() {
                @Override
                public void run() {
                    prefs.edit().putString(KEY_SERVER_URL, newUrl).apply();
                    Toast.makeText(MainActivity.this, "Connecting to: " + newUrl, Toast.LENGTH_SHORT).show();
                    webView.loadUrl(newUrl);
                }
            });
        }
    }

    @Override
    protected void onPause() {
        super.onPause();
        CookieManager.getInstance().flush();
    }

    @Override
    public boolean onKeyDown(int keyCode, KeyEvent event) {
        if (keyCode == KeyEvent.KEYCODE_BACK && webView.canGoBack()) {
            webView.goBack();
            return true;
        }
        return super.onKeyDown(keyCode, event);
    }
}
