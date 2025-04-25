import javax.crypto.Cipher;
import java.io.File;
import java.nio.file.Files;
import java.security.*;
import java.util.Base64;

public class RSAEncryptor {

    public static KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }

    public static String encryptFile(File file, KeyPair keyPair) throws Exception {
        byte[] fileBytes = Files.readAllBytes(file.toPath());
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
        byte[] encrypted = cipher.doFinal(fileBytes);
        return Base64.getEncoder().encodeToString(encrypted);
    }
}
