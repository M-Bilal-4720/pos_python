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
    private static final String DEFAULT_URL = "http://192.168.50.53:5000/water";

    private WebView webView;
    private ProgressBar progressBar;
    private SharedPreferences prefs;

    @SuppressLint("SetJavaScriptEnabled")
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        prefs = getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
        String serverUrl = prefs.getString(KEY_SERVER_URL, DEFAULT_URL);

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
        ws.setCacheMode(WebSettings.LOAD_DEFAULT);

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
                view.loadUrl(request.getUrl().toString());
                return true;
            }}
        );

        webView.loadUrl(serverUrl);
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
    public boolean onKeyDown(int keyCode, KeyEvent event) {
        if (keyCode == KeyEvent.KEYCODE_BACK && webView.canGoBack()) {
            webView.goBack();
            return true;
        }
        return super.onKeyDown(keyCode, event);
    }
}
