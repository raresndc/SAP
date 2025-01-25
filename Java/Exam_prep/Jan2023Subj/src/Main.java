import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Base64;
import java.util.Enumeration;

public class Main {

    public static String getHexString(byte[] value) {
        StringBuilder result = new StringBuilder();
        result.append("0x");
        for (byte b : value) {
            result.append(String.format(" %02X", b));
        }
        return result.toString();
    }

    public static byte[] hexStringToByteArray(String hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i + 1), 16));
        }
        return data;
    }

    public static byte[] getHash(byte[] input, String algorithm) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance(algorithm);
        return md.digest(input);
    }

    public static String decrypt(
            String filename,
            String password,
            String algorithm) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {

        // Ensure IV setup
        byte[] IV = new byte[16]; // AES block size is 16 bytes
        IV[10] = (byte) 0xFF;    // Set the byte with index 10 to 0xFF

        File inputFile = new File(filename);
        if (!inputFile.exists()) {
            throw new UnsupportedOperationException("Missing file");
        }

        FileInputStream fis = new FileInputStream(inputFile);

        Cipher cipher = Cipher.getInstance(algorithm + "/CBC/NoPadding");

        SecretKeySpec key = new SecretKeySpec(password.getBytes(), algorithm);
        IvParameterSpec ivSpec = new IvParameterSpec(IV);

        cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);

        ByteArrayOutputStream decryptedOutput = new ByteArrayOutputStream(); // To collect decrypted bytes
        byte[] buffer = new byte[cipher.getBlockSize()];
        int noBytes;

        // Process file content
        while ((noBytes = fis.read(buffer)) != -1) {
            byte[] cipherBlock = cipher.update(buffer, 0, noBytes);
            if (cipherBlock != null) {
                decryptedOutput.write(cipherBlock);
            }
        }
        // Finalize decryption
        byte[] lastBlock = cipher.doFinal();
        if (lastBlock != null) {
            decryptedOutput.write(lastBlock);
        }

        fis.close();

        // Convert decrypted bytes to String
        return new String(decryptedOutput.toByteArray(), StandardCharsets.UTF_8);
    }

    public static byte[] getPBKDF(
            String userPassword,
            String algorithm,
            String salt,
            int noIterations
    ) throws NoSuchAlgorithmException, InvalidKeySpecException {

        SecretKeyFactory pbkdf =
                SecretKeyFactory.getInstance(algorithm);
        PBEKeySpec pbkdfSpecifications =
                new PBEKeySpec(
                        userPassword.toCharArray(),
                        salt.getBytes(),
                        noIterations,160);
        SecretKey secretKey = pbkdf.generateSecret(pbkdfSpecifications);
        return secretKey.getEncoded();

    }

    public static KeyStore getKeyStore(
            String keyStoreFile,
            String keyStorePass,
            String keyStoreType) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
        File file = new File(keyStoreFile);
        if(!file.exists()) {
            throw new UnsupportedOperationException("Missing key store file");
        }

        FileInputStream fis = new FileInputStream(file);

        KeyStore ks = KeyStore.getInstance(keyStoreType);
        ks.load(fis, keyStorePass.toCharArray());

        fis.close();
        return ks;
    }

    public static void list(KeyStore ks) throws KeyStoreException {
        System.out.println("Key store content: ");
        Enumeration<String> aliases = ks.aliases();

        while(aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            System.out.println("Entry: " + alias);
            if(ks.isCertificateEntry(alias)) {
                System.out.println("-- Is a certificate");
            }
            if(ks.isKeyEntry(alias)) {
                System.out.println("-- Is a key pair");
            }
        }
    }

    public static PublicKey getPublicKey(String alias, KeyStore ks) throws KeyStoreException {
        if(ks == null) {
            throw new UnsupportedOperationException("Missing Key Store");
        }
        if(ks.containsAlias(alias)) {
            return ks.getCertificate(alias).getPublicKey();
        } else {
            return null;
        }
    }

    public static PrivateKey getPrivateKey(
            String alias, String keyPass, KeyStore ks ) throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException {
        if(ks == null) {
            throw new UnsupportedOperationException("Missing Key Store");
        }
        if(ks.containsAlias(alias)) {
            return (PrivateKey) ks.getKey(alias, keyPass.toCharArray());
        } else {
            return null;
        }
    }

    public static PublicKey getCertificateKey(String certificateFile) throws CertificateException, IOException {
        File file = new File(certificateFile);
        if(!file.exists()) {
            throw new UnsupportedOperationException("****Missing file****");
        }
        FileInputStream fis = new FileInputStream(file);

        CertificateFactory certFactory =
                CertificateFactory.getInstance("X.509");
        X509Certificate certificate =
                (X509Certificate) certFactory.generateCertificate(fis);
        fis.close();
        return certificate.getPublicKey();
    }

    public static byte[] signFile(String filename, PrivateKey key) throws IOException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        File file = new File(filename);
        if(!file.exists()) {
            throw new FileNotFoundException();
        }
        FileInputStream fis = new FileInputStream(file);

        byte[] fileContent = fis.readAllBytes();

        fis.close();

        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(key);

        signature.update(fileContent);
        return signature.sign();
    }

    public static boolean hasValidSignature(
            String filename, PublicKey key, byte[] signature) throws IOException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {

        File file = new File(filename);
        if(!file.exists()) {
            throw new FileNotFoundException();
        }

        FileInputStream fis = new FileInputStream(file);
        byte[] fileContent = fis.readAllBytes();
        fis.close();

        Signature signatureModule = Signature.getInstance("SHA256withRSA");
        signatureModule.initVerify(key);

        signatureModule.update(fileContent);
        return signatureModule.verify(signature);

    }

    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, InvalidKeySpecException, CertificateException, KeyStoreException, UnrecoverableKeyException, SignatureException {
        String b64Hash = "igVC8gV9HLh2eIWE+dRwGKKxohH9202mxcKcItFkTYk=";
        byte[] hash = Base64.getDecoder().decode(b64Hash);
        String password = "userfilepass]9#1";
        byte[] IV = new byte[0];

        File directory = new File("users");
        if (!directory.isDirectory()) {
            throw new RuntimeException("DIRECTORY isn t there!");
        } else {
            for (File file : directory.listFiles()) {
                byte[] fileContent  = Files.readAllBytes(file.toPath());
//                String fileContentString = new String(fileContent, StandardCharsets.UTF_8);

                byte[] fileHash = getHash(fileContent, "SHA-256");
                if(Arrays.equals(fileHash, hash)) {
                    System.out.println("File is: " + file.getName());

                    System.out.println("\nPassword is: ");
                    String userPass = decrypt(file.getAbsolutePath(), password, "AES");
                    System.out.println(userPass);

                    byte[] res = getPBKDF(userPass, "PBKDF2WithHmacSHA1", "ism2021", 150);
                    File dataFile = new File("result.dat");
                    if(!dataFile.exists()) {
                        dataFile.createNewFile();
                    }
                    FileOutputStream fos = new FileOutputStream(dataFile);
                    BufferedOutputStream bos = new BufferedOutputStream(fos);
                    DataOutputStream dos = new DataOutputStream(bos);

                    dos.write(res);
                    dos.close();

                    KeyStore ks = getKeyStore(
                            "ismkeystore.ks", "passks", "pkcs12");
                    list(ks);

                    PublicKey pubIsm1 = getPublicKey("ismkey1", ks);
                    PrivateKey privIsm1 = getPrivateKey("ismkey1", "passks", ks);

                    System.out.println("Public key:");
                    System.out.println(getHexString(pubIsm1.getEncoded()));
                    System.out.println("Private key");
                    System.out.println(getHexString(privIsm1.getEncoded()));

                    PublicKey pubIsm1FromCert =
                            getCertificateKey("ISMCertificateX509.cer");
                    System.out.println("Public key from certificate: ");
                    System.out.println(getHexString(pubIsm1FromCert.getEncoded()));

                    byte[] signature =
                            signFile("result.dat", privIsm1);

                    System.out.println("Digital signature value: ");
                    System.out.println(getHexString(signature));

                    if(hasValidSignature(
                            "result.dat", pubIsm1FromCert, signature))
                    {
                        System.out.println("File is the original one");
                    } else {
                        System.out.println("File has been changed");
                    }

                    break;
                }
            }
        }
    }
}