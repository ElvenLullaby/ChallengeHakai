package com.example.rasputinjava;

import android.app.Activity;
import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.Debug;
import java.io.IOException;
import java.net.Socket;
import android.app.ActivityManager;
import java.net.InetSocketAddress;
import android.util.Base64;
import okhttp3.CertificatePinner;
import okhttp3.Handshake;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.List;
import android.util.Base64;
import java.util.List;
import java.util.concurrent.TimeUnit;

import java.io.File;



public class RASPutin {
    // Verifica se o aplicativo está em modo debuggable
    public boolean debugCheck(Context context) {
        ApplicationInfo applicationInfo = context.getApplicationInfo();
        return (applicationInfo.flags & ApplicationInfo.FLAG_DEBUGGABLE) != 0;
    }

public void initialize(Context context) {
    // Método principal que inicializa todas as verificações de segurança
        boolean DebugChecker = debugCheck(context); // Verifica se há um debugger conectado
        boolean ultchecker = DevHasRoot_Check_Files(context); // Verifica se o dispositivo está rootado
        boolean emulator = emulatorTest();  // Verifica se está rodando em um emulador
        boolean suTry = isDeviceRooted_Try_Exec();  // Tenta executar comando 'su' para verificar root
        boolean detectDebugger = detectDebugger();  // Verifica se há um debugger conectado (método adicional)
        boolean HookDetection = HookDetection();  // Verifica se há manipulação em tempo real (hook)
        //boolean FridaDetectItself = FridaDetectItself();
//System.out.println(FridaDetectItself);
    // Se qualquer uma das verificações for positiva, bloqueia o aplicativo
            if (DebugChecker || ultchecker || emulator || suTry || detectDebugger) {
        lock((Activity) context);
    }
    }

    // Método para bloquear o aplicativo (finaliza todas as atividades)
    public void lock(Activity activity) {
        activity.finishAffinity();
    }
    // Verifica a presença de arquivos e pacotes associados a root
    public boolean DevHasRoot_Check_Files(Context context) {
        // Lista de caminhos de arquivos comuns associados ao root
        String[] suFiles = {
                "/sbin/su", "/system/bin/su", "/system/xbin/su", "/data/local/xbin/su",
                "/data/local/bin/su", "/system/sd/xbin/su", "/system/bin/failsafe/su",
                "/data/local/su", "/su/bin/su", "/system/bin/.ext/su", "/system/usr/we-need-root/su",
                "/cache/su", "/dev/su", "/data/su", "/su",
                "/system/app/Superuser.apk", "/system/app/SuperSU.apk", "/system/app/SuperSU",
                "/system/app/SuperSU/SuperSU.apk", "/system/app/Kinguser.apk", "/system/app/KingUser.apk",
                "/system/lib/libsu.so", "/system/lib64/libsu.so",
                "/data/data/com.noshufou.android.su/", "/data/data/eu.chainfire.supersu/",
                "/system/xbin/daemonsu", "/system/xbin/busybox",
                "/data/media/0/TWRP", "/sdcard/TWRP", "/data/TWRP",
                "./frida-server", "/data/local/tmp/frida-server",
                "/system/framework/root-access.jar", "/system/su.d",
                "/system/xbin/ku.sud", "/system/xbin/daemonsu", "/system/xbin/supolicy",
                "/system/xbin/supolicy.so", "/system/xbin/resize2fs_static",
                "/system/xbin/sush", "/system/xbin/busybox", "/system/xbin/busybox_mksh",
                "/system/xbin/busybox_insmod", "/system/xbin/busybox_rmmod", "/system/xbin/toybox",
                "/data/local/tmp/su", "/data/local/tmp/supolicy", "/data/local/tmp/busybox", "/data/local/tmp/magisk",
                "/data/local/tmp/frida-server", "/data/local/tmp/frida64", "/data/local/tmp/magiskhide",
                "/data/local/tmp/magiskcore","/data/adb/ksu","/system/lib/libc_malloc_debug_qemu.so",
                "/system/bin/qemud","/sys/qemu_trace","/system/bin/androVM-prop",
                "/system/bin/microvirt-prop","/dev/vboxguest","/dev/vboxuser",
                "/mnt/prebundledapps/","/system/bluestacks.prop","/system/bin/qemu-props",
                "/sys/devices/virtual/misc/qemu_pipe",
        };

        // Verifica se algum desses arquivos existe
        boolean filesExist = false;
        for (String filePath : suFiles) {
            if (new File(filePath).exists()) {
                filesExist = true;
                break;
            }
        }

        // Lista de pacotes associados ao root
        String[] superuserPackages = {
                "com.thirdparty.superuser", "eu.chainfire.supersu", "com.noshufou.android.su",
                "com.koushikdutta.superuser", "com.zachspong.temprootremovejb", "com.ramdroid.appquarantine",
                "com.topjohnwu.magisk", "com.devadvance.rootcloak", "com.devadvance.rootcloakplus",
                "de.robv.android.xposed.installer", "com.saurik.substrate", "com.amphoras.hidemyroot",
                "com.amphoras.hidemyrootadfree", "com.formyhm.hiderootPremium", "com.formyhm.hideroot",
                "com.noshufou.android.su.elite", "com.kingo.roo", "com.zhiqupk.root.global",
                "com.smedialink.oneclickroot", "com.alephzain.framaroo", "com.yellowes.su",
                "com.kingroot.kinguser", "stericson.busybox", "com.koushikdutta.rommanager",
                "com.koushikdutta.rommanager.license", "com.dimonvideo.luckypatcher",
                "com.chelpus.lackypatch", "com.ramdroid.appquarantinepro", "com.xmodgame",
                "com.cih.game_cih", "com.charles.lpoqasert", "catch_.me_.if_.you_.can_",
                "org.blackmart.market", "com.allinone.free", "com.repodroid.app",
                "org.creeplays.hack", "com.baseappfull.fwd", "com.zmapp", "com.dv.marketmod.installer",
                "org.mobilism.android", "com.android.wp.net.log", "com.android.camera.update",
                "cc.madkite.freedom", "com.solohsu.android.edxp.manager", "org.meowcat.edxposed.manager",
                "com.android.vending.billing.InAppBillingService.COIN",
                "com.android.vending.billing.InAppBillingService.LUCK", "com.chelpus.luckypatcher",
                "com.blackmartalpha", "com.topjohnwu.magisk", "com.catchingnow.icebox", "com.rootuninstaller.freezer",
                "com.hecorat.freezer", "com.genymotion.superuser", "com.genymotion.superuser",
                "com.genymotion.superuser", "de.robv.android.xposed.installer", "com.bluestacks", "com.bignox.app",
                "com.vphone.launcher", "com.android.emulator", "com.google.android.launcher.layouts.genymotion", "com.bluestacks.home",
        };

        // Verifica se algum dos pacotes superuser está instalado
        boolean isSuperuserInstalled = false;
        for (String packageName : superuserPackages) {
            try {
                context.getPackageManager().getPackageInfo(packageName, 0);
                isSuperuserInstalled = true;
                break;
            } catch (PackageManager.NameNotFoundException e) {
                // Pacote não encontrado, continua
            }
        }

        return filesExist || isSuperuserInstalled;
    }
    // Verifica se o dispositivo é um emulador baseado em características do sistema
    public boolean emulatorTest() {
        return (Build.BRAND.startsWith("generic") && Build.DEVICE.startsWith("generic"))
                || Build.FINGERPRINT.startsWith("generic")
                || Build.FINGERPRINT.startsWith("unknown")
                || Build.HARDWARE.contains("goldfish")
                || Build.HARDWARE.contains("ranchu")
                || Build.MODEL.contains("google_sdk")
                || Build.MODEL.contains("Emulator")
                || Build.MODEL.contains("Android SDK built for x86")
                || Build.MANUFACTURER.contains("Genymotion")
                || Build.PRODUCT.contains("sdk_google")
                || Build.PRODUCT.contains("google_sdk")
                || Build.PRODUCT.contains("sdk")
                || Build.PRODUCT.contains("sdk_x86")
                || Build.PRODUCT.contains("sdk_gphone64_arm64")
                || Build.PRODUCT.contains("vbox86p")
                || Build.PRODUCT.contains("emulator")
                || Build.PRODUCT.contains("simulator");
    }
    // Tenta executar o comando 'su' para verificar se o dispositivo está rootado
    public boolean isDeviceRooted_Try_Exec() {
        Process process = null;
        try {
            process = Runtime.getRuntime().exec("su");
            return true; // Se conseguir executar 'su', o dispositivo está rootado
        } catch (Exception e) {
            return false; // Se falhar, provavelmente não está rootado
        } finally {
            if (process != null) {
                process.destroy();
            }
        }
    }
    // Verifica se há um debugger conectado ao aplicativo
    public boolean detectDebugger() {
        return Debug.isDebuggerConnected();
    }
    // Método para detecção de hooks

    /*public static boolean FridaDetectItself() {
        for (int i = 0; i <= 65535; i++) {
            try (Socket sock = new Socket("localhost", i)) {
                sock.getOutputStream().write(0);
                sock.getOutputStream().write("AUTH\r\n".getBytes());

                Thread.sleep(100);

                byte[] res = new byte[7];
                int ret = sock.getInputStream().read(res);

                if (ret != -1 && new String(res, 0, 6).equals("REJECT")) {
                    return true;
                }
            } catch (IOException | InterruptedException e) {
                return false;
            }
        }
        return false;
    }*/
}

/*public class SSLPinning {
    // Hash esperado do certificado do servidor
    private String expectedHash;
    // Domínio do servidor a ser verificado
    private String domain;
    // Cliente HTTP configurado com o certificado pinado
    private OkHttpClient client;

    // Construtor que inicializa o domínio
    public SSLPinning(String domain) {
        this.domain = domain;
    }

    // Método para definir o hash esperado e atualizar o cliente
    public void setExpectedHash(String hash) {
        this.expectedHash = hash;
        updateClient();
    }

    // Método privado para atualizar o cliente com o novo hash
    private void updateClient() {
        // Cria um CertificatePinner com o hash esperado
        CertificatePinner certificatePinner = new CertificatePinner.Builder()
                .add(domain, "sha256/" + expectedHash)
                .build();

        // Configura um novo OkHttpClient com o CertificatePinner
        this.client = new OkHttpClient.Builder()
                .certificatePinner(certificatePinner)
                .connectTimeout(30, TimeUnit.SECONDS)
                .readTimeout(30, TimeUnit.SECONDS)
                .build();
    }

    // Método para validar o certificado do servidor
    public boolean validateCertificate() {
        if (expectedHash == null || client == null) {
            throw new IllegalStateException("Expected hash not set. Call setExpectedHash() first.");
        }

        try {
            // Cria uma requisição para o domínio
            Request request = new Request.Builder()
                    .url("https://" + domain)
                    .build();

            // Executa a requisição e verifica se foi bem-sucedida
            Response response = client.newCall(request).execute();
            response.close();
            return response.isSuccessful();
        } catch (Exception e) {
            // Se ocorrer uma exceção (incluindo CertificatePinningException), retorna false
            e.printStackTrace();
            return false;
        }
    }

    // Método para obter o hash do certificado atual do servidor
    public String getSiteCertificateHash() {
        try {
            // Cria um cliente temporário sem pinning
            OkHttpClient tempClient = new OkHttpClient.Builder()
                    .connectTimeout(30, TimeUnit.SECONDS)
                    .readTimeout(30, TimeUnit.SECONDS)
                    .build();

            // Cria uma requisição para o domínio
            Request request = new Request.Builder()
                    .url("https://" + domain)
                    .build();

            // Executa a requisição e obtém o handshake SSL
            Response response = tempClient.newCall(request).execute();
            Handshake handshake = response.handshake();
            response.close();

            if (handshake == null) return null;

            // Obtém os certificados do handshake
            List<X509Certificate> certificates = (List<X509Certificate>) handshake.peerCertificates();
            if (certificates.isEmpty()) return null;

            // Pega o primeiro certificado (geralmente o do servidor)
            X509Certificate certificate = certificates.get(0);

            // Calcula o hash SHA-256 da chave pública do certificado
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] publicKey = certificate.getPublicKey().getEncoded();
            byte[] hashBytes = digest.digest(publicKey);

            // Retorna o hash como uma string Base64
            return Base64.encodeToString(hashBytes, Base64.NO_WRAP);
        } catch (IOException | NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
    }
}
*\



