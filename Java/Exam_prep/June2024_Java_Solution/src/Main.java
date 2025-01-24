import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

public class Main {

    public static String getHexString(byte[] value) {
        StringBuilder result = new StringBuilder();
        result.append("0x");
        for(byte b : value) {
            result.append(String.format(" %02X", b));
        }
        return result.toString();
    }

    public static byte[] getHash(String input, String algorithm) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance(algorithm);
        return md.digest(input.getBytes());
    }

    public static void encrypt(
            String filename,
            String cipherFilename,
            String password,
            String algorithm) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, NoSuchPaddingException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {


        //IV is known/generated and placed in the cipher file at the beginning

        File inputFile = new File(filename);
        if(!inputFile.exists()) {
            throw new UnsupportedOperationException("Missing file");
        }
        File cipherFile = new File(cipherFilename);
        if(!cipherFile.exists()) {
            cipherFile.createNewFile();
        }

        FileInputStream fis = new FileInputStream(inputFile);
        FileOutputStream fos = new FileOutputStream(cipherFile);

        Cipher cipher = Cipher.getInstance(algorithm + "/CBC/PKCS5Padding");

        //IV has the 5th byte from left to right all bits 1
        byte[] IV = new byte[cipher.getBlockSize()];
        IV[5] = (byte) 0xCC;

        SecretKeySpec key = new SecretKeySpec(password.getBytes(), algorithm);
        IvParameterSpec ivSpec = new IvParameterSpec(IV);

        cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);

        byte[] buffer = new byte[cipher.getBlockSize()];
        int noBytes = 0;

        while(true) {
            noBytes = fis.read(buffer);
            if(noBytes == -1) {
                break;
            }
            byte[] cipherBlock = cipher.update(buffer, 0, noBytes);
            fos.write(cipherBlock);
        }
        //get the last ciphertext block
        byte[] lastBlock = cipher.doFinal();
        fos.write(lastBlock);

        fis.close();
        fos.close();
    }

    public static void decrypt(
            String filename,
            String outputFile,
            String password,
            String algorithm) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {


        //IV the cipher file at the beginning

        File inputFile = new File(filename);
        if(!inputFile.exists()) {
            throw new UnsupportedOperationException("Missing file");
        }
        File outFile = new File(outputFile);
        if(!outFile.exists()) {
            outFile.createNewFile();
        }

        FileInputStream fis = new FileInputStream(inputFile);
        FileOutputStream fos = new FileOutputStream(outFile);

        Cipher cipher = Cipher.getInstance(algorithm + "/CBC/PKCS5Padding");

        byte[] IV = new byte[cipher.getBlockSize()];
        IV[5] = (byte) 0xCC;

        SecretKeySpec key = new SecretKeySpec(password.getBytes(), algorithm);
        IvParameterSpec ivSpec = new IvParameterSpec(IV);

        cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);

        byte[] buffer = new byte[cipher.getBlockSize()];
        int noBytes = 0;

        while(true) {
            noBytes = fis.read(buffer);
            if(noBytes == -1) {
                break;
            }
            byte[] cipherBlock = cipher.update(buffer, 0, noBytes);
            fos.write(cipherBlock);
        }
        byte[] lastBlock = cipher.doFinal();
        fos.write(lastBlock);

        fis.close();
        fos.close();
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


    public static void main(String[] args) {
        byte[] hash = new byte[0];
        File file = new File("msg.txt");
        if(!file.exists()) {
            throw new UnsupportedOperationException("FILE is not there");
        }

        try {
            FileReader fr = new FileReader(file);
            BufferedReader br = new BufferedReader(fr);

            String line;
            while((line = br.readLine()) != null) {
                hash = getHash(line, "SHA-256");
            }
        } catch (NoSuchAlgorithmException | IOException e) {
            throw new RuntimeException(e);
        }

        System.out.println("Hash from msg.txt: " + getHexString(hash));
        System.out.println("\n");

        try {
            encrypt(file.getName(), "enc_msg.aes", "passwordsecurity", "AES");
            decrypt("enc_msg.aes", "msg_verification.txt", "passwordsecurity", "AES");
        } catch (IOException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException |
                 IllegalBlockSizeException | BadPaddingException | InvalidAlgorithmParameterException e) {
            throw new RuntimeException(e);
        }


        KeyStore ks = null;
        try {
            ks = getKeyStore(
                    "sap_exam_keystore.ks", "you_already_made_it", "pkcs12");
            list(ks);

            PublicKey pubIsm1 = getPublicKey("sapexamkey", ks);
            PrivateKey privIsm1 = getPrivateKey("sapexamkey", "you_already_made_it", ks);

            System.out.println("Public key:");
            System.out.println(getHexString(pubIsm1.getEncoded()));
            System.out.println("Private key");
            System.out.println(getHexString(privIsm1.getEncoded()));
            System.out.println("\n");

            PublicKey pubIsm1FromCert =
                    getCertificateKey("SAPExamCertificateX509.cer");
            System.out.println("Public key from certificate: ");
            System.out.println(getHexString(pubIsm1FromCert.getEncoded()));

            byte[] signature = signFile("enc_msg.aes", privIsm1);

            System.out.println("Digital signature value: ");
            System.out.println(getHexString(signature));
            System.out.println("\n");

            if(hasValidSignature("enc_msg.aes", pubIsm1FromCert, signature))
            {
                System.out.println("File is the original one");
            } else {
                System.out.println("File has been changed");
            }

        } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException |
                 UnrecoverableKeyException | SignatureException | InvalidKeyException e) {
            throw new RuntimeException(e);
        }
    }
}