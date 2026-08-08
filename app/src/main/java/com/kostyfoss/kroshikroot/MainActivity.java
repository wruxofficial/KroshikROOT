package com.kostyfoss.kroshikroot;

import androidx.appcompat.app.AppCompatActivity;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.Toast;

public class MainActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        Button btnRoot = findViewById(R.id.btnRoot);

        btnRoot.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                int apiLevel = android.os.Build.VERSION.SDK_INT;
                String kernelVersion = System.getProperty("os.version");

                if (apiLevel >= 29 && apiLevel <= 32) {
                    Toast.makeText(MainActivity.this, "Kroshik ready! KERNEL: " + kernelVersion, Toast.LENGTH_SHORT).show();

                    boolean isVulnerable = ExploitEngine.runKroshikExploit(kernelVersion);

                    if (isVulnerable) {
                        Toast.makeText(MainActivity.this, "Exploit triggered successfully!", Toast.LENGTH_LONG).show();
                    } else {
                        Toast.makeText(MainActivity.this, "Kernel is not vulnerable or exploit failed.", Toast.LENGTH_SHORT).show();
                    }
                } else {
                    Toast.makeText(MainActivity.this, "Root is only for android 10-12", Toast.LENGTH_LONG).show();
                }
            }
        });
    }
}
