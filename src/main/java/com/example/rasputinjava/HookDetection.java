package com.example.rasputinjava;

import android.app.ActivityManager;
import android.content.Context;

import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.List;

public class HookDetection {
    // Método para detectar a presença do Frida nos processos em execução
    public static boolean Frisk(Context context) {
        boolean returnValue = false;

        // Obtém o gerenciador de atividades do sistema
        ActivityManager manager = (ActivityManager) context.getSystemService(Context.ACTIVITY_SERVICE);
        // Obtém uma lista de todos os serviços em execução
        List<ActivityManager.RunningServiceInfo> list = manager.getRunningServices(Integer.MAX_VALUE);

        if (list != null) {
            // Itera sobre todos os serviços em execução
            for (ActivityManager.RunningServiceInfo serviceInfo : list) {
                // Verifica se o nome do processo contém "frida" (case-insensitive)
                if (serviceInfo.process.toLowerCase().contains("frida")) {
                    returnValue = true;
                    break;
                }
            }
        }

        return returnValue;
    }

    // Método para detectar o Frida procurando por portas abertas específicas
    public static Pair<Boolean, Integer> Frisk2() {
        // Itera sobre todas as portas possíveis
        for (int i = 0; i <= 65535; i++) {
            try {
                Socket sock = new Socket();
                // Tenta conectar à porta local com um timeout de 100ms
                sock.connect(new InetSocketAddress("localhost", i), 100);
                OutputStream outputStream = sock.getOutputStream();
                // Envia uma mensagem de autenticação específica do Frida
                outputStream.write(0);
                outputStream.write("AUTH\r\n".getBytes());
                outputStream.flush();

                Thread.sleep(100);

                byte[] res = new byte[7];
                InputStream inputStream = sock.getInputStream();
                int ret = inputStream.read(res);

                // Verifica se a resposta é "REJECT", que é típica do Frida
                if (ret != -1 && new String(res, 0, 6).equals("REJECT")) {
                    sock.close();
                    return new Pair<>(true, i);  // Retorna true e a porta encontrada
                }

                sock.close();
            } catch (Exception e) {
                // Conexão falhou, continua para a próxima porta
            }
        }
        return new Pair<>(false, -1);  // Nenhuma porta do Frida encontrada
    }

    // Método para verificar se a porta padrão do Frida (27042) está aberta
    public static boolean Frisk3() {
        String serverAddress = "127.0.0.1";
        int serverPort = 27042;  // Porta padrão do Frida

        try {
            Socket socket = new Socket();
            // Tenta conectar à porta padrão do Frida com um timeout de 1000ms
            socket.connect(new InetSocketAddress(serverAddress, serverPort), 1000);
            socket.close();
            return true;  // Conexão bem-sucedida, Frida provavelmente presente
        } catch (Exception e) {
            return false;  // Conexão falhou, Frida provavelmente não está presente
        }
    }

    // Classe interna para representar um par de valores
    public static class Pair<T, U> {
        public final T first;
        public final U second;

        public Pair(T first, U second) {
            this.first = first;
            this.second = second;
        }
    }
}