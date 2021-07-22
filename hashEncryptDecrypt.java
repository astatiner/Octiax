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
    public static void main(String[] args) {
        Scanner sc = new Scanner(System.in);
        System.out.println("Enter 'HASH' to hash a string, 'ENCRYPT' to encrypt a string, 'DECRYPT' a string.");
        System.out.println("Hashing algorithm: SHA256, Encryption and Decryption algorithm: AES128");
        String cmd = sc.nextLine();
        if(cmd.toLowerCase().equals("hash"))
        {
            hashString();
        }

        else if(cmd.toLowerCase().equals("encrypt"))
        {
            encryptString();
        }

        else if(cmd.toLowerCase().equals("decrypt"))
        {
            decryptString();
        }
    }

    public static void hashString() {
        System.out.println("Hash String");
    }

    public static void encryptString() {
        System.out.println("Encrypt String");
    }

    public static String decryptString(String toDecrypt) {
        Scanner dsc = new Scanner(System.in);
        System.out.println("String decryption: AES128 (CBC)");
        System.out.println("Enter string to decrypt: ");
        String toDecrypt = dsc.nextLine();
        System.out.println("Enter initialization vector: ");
        System.out.println("If none, enter 'ivnull'");
        String inVector = dsc.nextLine();
        System.out.println("Enter secret key: ");
        String secKey = dsc.nextLine();

        if(toDecrypt.equals("")||secKey.equals("")||secKey.length()!=16)
        {
            System.out.println("Invalid key");
        }

        else
        {

        }
    }
}