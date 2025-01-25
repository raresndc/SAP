import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.file.Files;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.*;

public class Main {

    public static String getHexString(byte[] value) {
        StringBuilder result = new StringBuilder();
        result.append("0x");
        for(byte b : value) {
            result.append(String.format(" %02X", b));
        }
        return result.toString();
    }

    public static byte[] getHash(byte[] input, String algorithm) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance(algorithm);
        return md.digest(input);
    }

    public static void decrypt(
            String filename,
            String outputFile,
            byte[] password,
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

        //getting the IV from the file
        byte[] IV = new byte[cipher.getBlockSize()];
        IV[15] = 23;
        IV[14] = 20;
        IV[13] = 2;
        IV[12] = 3;

        SecretKeySpec key = new SecretKeySpec(password, algorithm);
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

    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, CertificateException, KeyStoreException, UnrecoverableKeyException, SignatureException {

        Map<String, byte[]> mappedFingerprints = new HashMap<>();
        File fingerprintsFile = new File("sha2Fingerprints.txt");

        FileReader fr = new FileReader(fingerprintsFile);
        BufferedReader br = new BufferedReader(fr);
        String line = null;
        while((line = br.readLine())!= null) {
            mappedFingerprints.put(line, Base64.getDecoder().decode(br.readLine()));
        }
        br.close();

//        mappedFingerprints.forEach((key, value) -> System.out.println(key + " " + value));

        File directory = new File("system32");
        if(!directory.isDirectory()) {
            throw new RuntimeException("This is not a directory!");
        } else {
            for(File file : directory.listFiles()) {
                byte[] fileBytes = Files.readAllBytes(file.toPath());
                byte[] hashedFileContent = getHash(fileBytes, "SHA-256");

                byte[] fileHash = mappedFingerprints.get(file.getPath());

                if(!Arrays.equals(hashedFileContent, fileHash)) {
                    System.out.println("Changed file is: " + file.getName());

                    byte[] password = Files.readAllBytes(file.toPath());
                    decrypt("financialdata.enc", "financialdata.txt", password, "AES");

                    FileReader fileReader = new FileReader("financialdata.txt");
                    BufferedReader bufferedReader = new BufferedReader(fileReader);
                    String lineFin = bufferedReader.readLine();
                    bufferedReader.close();
                    fileReader.close();

                    File outputFile = new File("myresponse.txt");
                    FileWriter fw = new FileWriter(outputFile);
                    BufferedWriter bw = new BufferedWriter(fw);
                    bw.write(lineFin);
                    bw.close();
                    fw.close();

                    KeyStore ks = getKeyStore(
                            "ismkeystore.ks", "passks", "pkcs12");
                    list(ks);

                    PublicKey pubIsm1 = getPublicKey("ismkey1", ks);
                    PrivateKey privIsm1 = getPrivateKey("ismkey1", "passks", ks);

                    PublicKey pubIsm1FromCert = getCertificateKey("ISMCertificateX509.cer");

                    byte[] signature = signFile("myresponse.txt", privIsm1);

                    if(hasValidSignature(
                            "myresponse.txt", pubIsm1FromCert, signature))
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