package org.example;

import javax.crypto.*;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.KeySpec;

public class Main {
    //si no especificamos el algoritmo, por defecto tendrá un padding de PKCS5 y un modo de operación de ECB. este modo
    //se desaconseja por ser inseguro.
    //https://javadoc.sic.tech/iaik_jce/current/index.html?iaik/security/cipher/Rijndael.html
    //por otro lado, AES es una implementación del algoritmo Rijndael, y además se encuentra
    //completamente integrado en Java. Si quisieramos usar Rijndael, tendriamos que usar proveedores como Bouncy Castle

    private static final String ALGORITHM = "AES";
    private static final String FILE_NAME = "fichero.cifrado";

    public static void main(String[] args) {
        String usuario = "root";
        String pass = "root";
        String texto = "prueba encriptación";

        //1 clave a partir de usuario + password
        SecretKey key = generarClave(usuario + pass);

        //2 encriptar
        byte[] textoCifrado = encriptar(texto, key);

        //3 guardar en fichero
        guardarFile(textoCifrado);

        //4 descifrar
        byte[] contenidoCifrado = leerFile();
        String textoDescifrado = desencriptar(contenidoCifrado, key);

        //5 comprobar si el texto del fichero es el mismo que el que le pasamos
        System.out.println(texto.equals(textoDescifrado));
    }

    /**
     * Genera una clave secreta a partir de un string de texto,
     * usando el algoritmo PBKDF2WithHmacSHA256.
     * La clave se generará con 128 bits de longitud y se
     * realizarán 65536 iteraciones con el algoritmo hash
     * @param seed           el string de texto que se utilizará como semilla
     * @return la clave generada
     */
    private static SecretKey generarClave(String seed) {
        try {
            byte[] salt = new byte[16];
            SecureRandom sr = new SecureRandom();
            sr.nextBytes(salt);
            //the iterationcount is the number of times the hash function is applied
            KeySpec spec = new PBEKeySpec(seed.toCharArray(), salt, 65536, 128); // 128 bits = 16 bytes
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            byte[] keyBytes = factory.generateSecret(spec).getEncoded();

            return new SecretKeySpec(keyBytes, "AES");
        } catch (Exception e) {
            throw new RuntimeException("Error generando clave", e);
        }
    }


    /**
     * Encripta un texto utilizando una clave AES.
     *
     * @param texto texto a encriptar
     * @param key   clave AES para encriptar
     * @return el texto encriptado
     */
    private static byte[] encriptar(String texto, SecretKey key) {
        try {
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, key);
            return cipher.doFinal(texto.getBytes(StandardCharsets.UTF_8));
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException |
                 BadPaddingException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Desencripta un texto cifrado utilizando una clave AES.
     *
     * @param contenidoCifrado el texto cifrado a desencriptar
     * @param key              clave AES para desencriptar
     * @return el texto desencriptado
     */
    private static String desencriptar(byte[] contenidoCifrado, SecretKey key) {
        try {
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, key);
            byte[] resultado = cipher.doFinal(contenidoCifrado);
            return new String(resultado, StandardCharsets.UTF_8);
        } catch (NoSuchPaddingException | NoSuchAlgorithmException | InvalidKeyException | BadPaddingException |
                 IllegalBlockSizeException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Lee el contenido del archivo {@link Main#FILE_NAME} y lo devuelve
     * como un array de bytes.
     *
     * @return el contenido del archivo encriptado
     */
    private static byte[] leerFile() {
        File archivo = new File(Main.FILE_NAME);
        byte[] datos = new byte[(int) archivo.length()];
        try (FileInputStream fis = new FileInputStream(archivo)) {
            fis.read(datos);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        return datos;
    }

    /**
     * Guarda el contenido encriptado en el archivo {@link Main#FILE_NAME}.
     *
     * @param textoCifrado el contenido encriptado a guardar
     */
    private static void guardarFile(byte[] textoCifrado) {
        try (FileOutputStream fos = new FileOutputStream(Main.FILE_NAME)) {
            fos.write(textoCifrado);

        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}