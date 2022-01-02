import java.io.*;
import java.awt.datatransfer.StringSelection;
import java.awt.Toolkit;
import java.awt.datatransfer.Clipboard;
import java.util.*;
import java.awt.Desktop;
import java.net.URI;
import javax.crypto.Cipher;
import java.security.MessageDigest;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import org.apache.commons.codec.binary.Base64;

public class hashEncryptDecrypt {
    public static void main(String[] args) throws Exception{
        Scanner sc = new Scanner(System.in);
        System.out.println("Enter 'HASH' to hash a string, 'ENCRYPT' to encrypt a string, 'DECRYPT' a string.");
        System.out.println("Hashing algorithm: SHA256, Encryption and Decryption algorithm: AES128");
        String cmd = sc.nextLine();
        if(cmd.toLowerCase().equals("hash"))
        {
            System.out.println("Enter the string to hash: ");
            String hashInput = sc.nextLine();
            System.out.println("Output:"+hashString(hashInput));
        }

        else if(cmd.toLowerCase().equals("encrypt"))
        {
            System.out.println("Enter the string to encrypt: ");
            String encryptInput = sc.nextLine();
            System.out.println("Enter the initialization vector: ");
            String initInput = sc.nextLine();
            System.out.println("Enter the secretive key: ");
            String keyInput = sc.nextLine();
            System.out.println("Output: "+encryptString(encryptInput, initInput, keyInput));
        }

        else if(cmd.toLowerCase().equals("decrypt"))
        {
            System.out.println("Enter the string to decrypt: ");
            String decryptInput = sc.nextLine();
            System.out.println("Enter the initialization vector: ");
            String initInput = sc.nextLine();
            System.out.println("Enter the secretive key: ");
            String keyInput = sc.nextLine();
            System.out.println("Output: "+decryptString(decryptInput, initInput, keyInput));
        }
    }

    public static String hashString(String hashInput) throws Exception{
        MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
        messageDigest.update(hashInput.getBytes());
        byte[] stringHashArray = messageDigest.digest();
        StringBuilder sdbs = new StringBuilder();
        for(byte variable : stringHashArray)
        {
            sdbs.append(String.format("%02x",variable));
        }

        String result = sdbs.toString();

        return result;
    }
    public static String encryptString(String encryptInput, String initInput, String keyInput) throws Exception {
        IvParameterSpec iv = new IvParameterSpec(initInput.getBytes("UTF-8"));
        SecretKeySpec uskeySpec = new SecretKeySpec(keyInput.getBytes("UTF-8"),"AES");

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
        cipher.init(Cipher.ENCRYPT_MODE, uskeySpec, iv);

        byte[] encryptedUsername = cipher.doFinal(encryptInput.getBytes());
        return Base64.encodeBase64String(encryptedUsername); //E9*&gX@#Z93liFN0
    }
    public static String decryptString(String decryptInput, String initInput, String keyInput) throws Exception {
        IvParameterSpec iv = new IvParameterSpec(initInput.getBytes("UTF-8"));
        SecretKeySpec skeySpec = new SecretKeySpec(keyInput.getBytes("UTF-8"), "AES");

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
        cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);
        byte[] original = cipher.doFinal(Base64.decodeBase64(decryptInput));

        return new String(original);
    }
}