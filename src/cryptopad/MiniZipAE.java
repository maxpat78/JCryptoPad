/*
 * This JCryptoPad source code is hereby placed into the Public Domain by its Author maxpat78.
 */

package cryptopad;

import java.io.*;
import java.util.*;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.zip.*;
import javax.crypto.*;
import javax.crypto.spec.*;


class MiniZipException extends Exception {
    public MiniZipException(String message) {
        super(message);
    }
}

class ExtraFieldAE {
    byte[] szHeader = new byte[]{0x01, (byte)0x99};
    short wSize = 7;
    short wVersion = 1; // 1=AE-1 (stores CRC-32), 2=AE-2 (discards CRC-32)
    byte[] szVendor = new byte[]{0x41, 0x45}; // AE
    byte bStrength = 1; // 1=128-bit, 2=192-bit, 3=256-bit
    short wCompression = 8; // 0=Stored, 8=Deflated
    
    ExtraFieldAE() {}
    
    ExtraFieldAE(byte strength, short compression) {
        bStrength = strength;
        wCompression = compression;
    }
    
    byte[] asBytes() {
        ByteBuffer bb;
        bb = ByteBuffer.allocate(11);
        bb.order(ByteOrder.LITTLE_ENDIAN);
        bb.put(szHeader);
        bb.putShort(wSize);
        bb.putShort(wVersion);
        bb.put(szVendor);
        bb.put(bStrength);
        bb.putShort(wCompression);
        return bb.array();
    }
    
    void parse(byte[] data) throws MiniZipException {
        ByteBuffer bb;
        bb = ByteBuffer.wrap(data);
        bb.order(ByteOrder.LITTLE_ENDIAN);
        
        bb.get(szHeader);
        if ((szHeader[0] != 1 || szHeader[1] != (byte) 0x99) ||
        bb.getShort() != 7 || bb.getShort() != 1 ||
                bb.get()!='A' || bb.get()!='E')
            throw new MiniZipException("UNKNOWN AES HEADER");
        bStrength = bb.get();
        if (bStrength != 1 && bStrength != 3)
            throw new MiniZipException("UNSUPPORTED KEY LENGTH");
    }
}

class PKHeader {
    // Signature PKxx
    byte[] szSignature = new byte[]{0x50, 0x4B, 0x00, 0x00};
    short wVersionMadeBy = 0x33;
    short wVersionToExtract = 0x33;
    short wGPBitFlag = 1;
    short wCompressionMethod = 99; // 99=AES encrypted
    short wDOSModTime;
    short wDOSModDate;
    long dwCrc32;
    int dwCompressedSize;
    int dwUncompressedSize;
    short wFilenameLength = 0;
    short wExtraFieldLength = 11; // sizeof(AEHEADER)
    short wFileCommentLength = 0;
    short wDiskNumberStart = 0;
    short wInternalAttributes = 0;
    int dwExternalAttributes = 0x20; // DOS ARCHIVE attribute
    int dwLocalHeaderOffset = 0; // since it is the 1st item
    byte[] sFileName;
    ExtraFieldAE bbExtraField = new ExtraFieldAE();
    
    PKHeader() {
        // Records current date and time in DOS format
        Calendar t = Calendar.getInstance();
        wDOSModDate = (short) ((t.get(Calendar.YEAR)-1980) << 9 |
                t.get(Calendar.MONTH)+1 << 5 |
                t.get(Calendar.DAY_OF_MONTH));
        
        wDOSModTime = (short) (t.get(Calendar.HOUR_OF_DAY) << 11 |
                t.get(Calendar.MINUTE) << 5 |
                t.get(Calendar.SECOND)/2);
    }
    
    PKHeader(byte[] data) throws MiniZipException {
        ByteBuffer bb;
        bb = ByteBuffer.wrap(data);
        bb.order(ByteOrder.LITTLE_ENDIAN);
        
        byte[] sig = new byte[4];
        bb.get(sig);
        if (! Arrays.equals(sig, "PK\03\04".getBytes()) ||
           (bb.getShort() != 0x33 ||
                bb.getShort() != 1 ||
                bb.getShort() != 99))
            throw new MiniZipException("UNKNOWN LOCAL HEADER");
        bb.getShort();
        bb.getShort();
        dwCrc32 = bb.getInt();
        dwCompressedSize = bb.getInt();
        dwUncompressedSize = bb.getInt();
        wFilenameLength = bb.getShort();
        wExtraFieldLength = bb.getShort();
    }
    
    byte[] asBytesPK0304() {
        ByteBuffer bb;
        bb = ByteBuffer.allocate(41+wFilenameLength);
        bb.order(ByteOrder.LITTLE_ENDIAN);
        szSignature[2] = 0x03;
        szSignature[3] = 0x04;
        put_common_field(bb, false);
        bb.put(sFileName);
        bb.put(bbExtraField.asBytes());
        return bb.array();
    }
    
    byte[] asBytesPK0102() {
        ByteBuffer bb;
        bb = ByteBuffer.allocate(57+wFilenameLength);
        bb.order(ByteOrder.LITTLE_ENDIAN);
        szSignature[2] = 0x01;
        szSignature[3] = 0x02;
        put_common_field(bb, true);
        bb.putShort(wFileCommentLength);
        bb.putShort(wDiskNumberStart);
        bb.putShort(wInternalAttributes);
        bb.putInt(dwExternalAttributes);
        bb.putInt(dwLocalHeaderOffset);
        bb.put(sFileName);
        bb.put(bbExtraField.asBytes());
        return bb.array();
    }

    byte[] asBytesPK0506(byte[] comment) {
        ByteBuffer bb;
        bb = ByteBuffer.allocate(22+comment.length);
        bb.order(ByteOrder.LITTLE_ENDIAN);
        szSignature[2] = 0x05;
        szSignature[3] = 0x06;
        bb.put(szSignature);
        // This disk
        bb.putShort((short) 0);
        // Disk with Central Directory
        bb.putShort((short) 0);
        // Central Directory entries on this disk
        bb.putShort((short) 1);
        // Total Central Directory entries
        bb.putShort((short) 1);
        // Central Directory size
        bb.putInt(57+wFilenameLength);
        // Offset of Central Directory in this disk
        bb.putInt(41+wFilenameLength+dwCompressedSize);
        // Comment length
        bb.putShort((short) comment.length);
        bb.put(comment);
        return bb.array();
    }
    
    private void put_common_field(ByteBuffer bb, boolean isCentral) {
        bb.put(szSignature);
        if (isCentral)
            bb.putShort(wVersionMadeBy);
        bb.putShort(wVersionToExtract);
        bb.putShort(wGPBitFlag);
        bb.putShort(wCompressionMethod);
        bb.putShort(wDOSModTime);
        bb.putShort(wDOSModDate);
        bb.putInt((int) dwCrc32);
        bb.putInt(dwCompressedSize);
        bb.putInt(dwUncompressedSize);
        bb.putShort(wFilenameLength);
        bb.putShort(wExtraFieldLength);
    }
};

/**
 *
 * @author maxpat78
 */
public class MiniZipAE {
    PKHeader pkh = new PKHeader();
    private char[] zip_password;
    private String zip_comment;
    
    private byte[] salt;
    private byte[] passwordvv;
    private byte[] contents = null;
    private byte[] hmac_sha1_80;
    private int keysize;
    private int saltsize;
    
    MiniZipAE() {
        // WARNING: Unlimited Strength Java(TM) Cryptography
        // Extension (JCE) Policy Files *MUST* be installed manually,
        // or key size will be limited to 128 bits!
        try {
            if (Cipher.getMaxAllowedKeyLength("AES") > 128)
                set_aes_strength(3);
            else
                set_aes_strength(1);
        } catch (NoSuchAlgorithmException ex) {
        }
    }
    
    void set_password(char[] password) throws MiniZipException {
        if (password.length != 0)
            zip_password = password;
        else
            throw new MiniZipException("EMPTY ZIP PASSWORD");
    }
    
    void set_comment(String comment) {
        zip_comment = comment;
    }

    private void set_aes_strength(int strength) {
        if (strength == 1) {
            keysize = 16;
            saltsize = 8;
            pkh.bbExtraField.bStrength = 1;
        } 
        else if (strength == 3) {
            keysize = 32;
            saltsize = 16;
            pkh.bbExtraField.bStrength = 3;
        }
    }
    
    boolean append(String name, byte[] data) throws MiniZipException {
        pkh.sFileName = name.getBytes();
        pkh.wFilenameLength = (short) pkh.sFileName.length;
        
        pkh.dwUncompressedSize = data.length;
        
        // Calculates CRC-32 on uncompressed input
        CRC32 crc = new CRC32();
        crc.update(data);
        pkh.dwCrc32 = crc.getValue();
        
        // Deflates input
        // Sets the Deflater to max compression, without zlib headers
        Deflater compressor = new Deflater(9, true);
        compressor.setInput(data);
        compressor.finish();
        byte[] compressed = new byte[data.length+32];
        pkh.dwCompressedSize = compressor.deflate(compressed);
        compressor.end();
        
        // Generates a (secure) random salt
        salt = new byte[saltsize];
        SecureRandom rng = new SecureRandom();
        rng.nextBytes(salt);
        
        byte[] keys = AE_gen_keys(zip_password, salt);

        // Stores the password verification value
        passwordvv = Arrays.copyOfRange(keys, keysize*2, 2+keysize*2);
        
        contents = AES_ctr_le_crypt(Arrays.copyOfRange(keys, 0, keysize),
                compressed, pkh.dwCompressedSize);

        AE_authenticate(Arrays.copyOfRange(keys, keysize, 2*keysize));
        
        return true;
    }

    byte[] get() throws MiniZipException {
        byte[] keys = AE_gen_keys(zip_password, salt);
        if (! Arrays.equals(passwordvv, Arrays.copyOfRange(keys, keysize*2, 2+keysize*2)))
            throw new MiniZipException("BAD PASSWORD");
        
        byte[] stored_hmac = hmac_sha1_80;
        AE_authenticate(Arrays.copyOfRange(keys, keysize, 2*keysize));
        if (! Arrays.equals(stored_hmac, hmac_sha1_80))
            throw new MiniZipException("AUTHENTICATION FAILED");
        
        contents = AES_ctr_le_crypt(Arrays.copyOfRange(keys, 0, keysize),
                contents, pkh.dwCompressedSize);

        Inflater decompressor = new Inflater(true);
        decompressor.setInput(contents);
        byte[] output = new byte[pkh.dwUncompressedSize];
        try {
            int expandedLen = decompressor.inflate(output);
            if (expandedLen != pkh.dwUncompressedSize) 
                throw new MiniZipException("INFLATE ERROR");
        } catch (DataFormatException ex) {
            throw new MiniZipException("INFLATE ERROR");
        }
        decompressor.end();
        
        return output;
    }
    
    boolean read(DataInputStream zip) throws IOException, MiniZipException {
        PKHeader tpkh = null;
        byte[] header = new byte[30];
        zip.read(header);
        
        try {
            tpkh = new PKHeader(header);
        } catch (RuntimeException ex) {
        }
        
        if (tpkh == null) return false;
        
        tpkh.sFileName = new byte[tpkh.wFilenameLength];
        zip.read(tpkh.sFileName);
        
        byte[] aes_header = new byte[11];
        zip.read(aes_header);
        tpkh.bbExtraField.parse(aes_header);
        set_aes_strength(tpkh.bbExtraField.bStrength);

        salt = new byte[saltsize];
        zip.read(salt);

        passwordvv = new byte[2];
        zip.read(passwordvv);
        
        tpkh.dwCompressedSize -= (saltsize+12);
        contents = new byte[tpkh.dwCompressedSize];
        zip.read(contents);
        
        hmac_sha1_80 = new byte[10];
        zip.read(hmac_sha1_80);
        
        pkh = tpkh;
        
        return true;
    }
    
    void write(DataOutputStream zip) throws IOException {
        // Real size + salt + passwordvv(2) + HMAC(10)
        pkh.dwCompressedSize += (saltsize+12);
        zip.write(pkh.asBytesPK0304());
        
        // Actual file data
        zip.write(salt);
        zip.write(passwordvv);
        zip.write(contents);
        zip.write(hmac_sha1_80);
        
        zip.write(pkh.asBytesPK0102());
        
        zip.write(pkh.asBytesPK0506(zip_comment.getBytes()));
    }

    void AE_authenticate(byte[] key) {
        if (contents == null) return;
        
        // Gets the HMAC-SHA1-80 hash of the encrypted data
        Mac hmac = null;
        try {
            hmac = Mac.getInstance("HmacSHA1");
            SecretKeySpec hmac_key = new SecretKeySpec(key, "HmacSHA1");
            hmac.init(hmac_key);
        } catch (NoSuchAlgorithmException | InvalidKeyException ex) {
        }
        byte[] hash = hmac.doFinal(contents);
        hmac_sha1_80 = Arrays.copyOfRange(hash, 0, 10);
    }
    
    byte[] AE_gen_keys(char[] password, byte[] salt) {
        // Derives the AES and HMAC-SHA1-80 keys, plus 16-bit verification value
        byte[] keys = null;
        try {
            PBEKeySpec spec = new PBEKeySpec(password, salt, 1000, (2+2*keysize)*8);
            SecretKeyFactory skf;
            skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
            keys = skf.generateSecret(spec).getEncoded();
        } catch (NoSuchAlgorithmException | InvalidKeySpecException ex) {
        }
        return keys;
    }
    
    byte[] AES_ctr_le_crypt(byte[] key, byte[] data, int length) throws MiniZipException {
        // Encrypts with AES ECB, emulating CTR Little-Endian mode
        Cipher aes = null;
        try {
            aes = Cipher.getInstance("AES/ECB/NoPadding");
            SecretKeySpec aes_key = new SecretKeySpec(key, "AES");
            aes.init(Cipher.ENCRYPT_MODE, aes_key);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException ex) {
        } catch (InvalidKeyException ex) {
            throw new MiniZipException("AES KEY SIZE NOT SUPPORTED");
        }

        int i=0; // Global index in plain/cipher text
        long ctr_counter=1; // CTR counter start
        byte[] encrypted = new byte[length];

        // The CTR counter has 128 bits
        ByteBuffer bb;
        bb = ByteBuffer.allocate(16);
        bb.order(ByteOrder.LITTLE_ENDIAN);
        
aes_encrypt:        
        while (true) {
            // Converts 64-bit CTR counter to byte[], Little Endian
            bb.putLong(ctr_counter);

            // Encrypts the counter with AES-ECB
            byte[] ctr_counter_enc = null;
            try {
                ctr_counter_enc = aes.doFinal(bb.array());
            } catch (IllegalBlockSizeException | BadPaddingException ex) {
            }

            // XOR the plain text with the encrypted counter
            for (byte b: ctr_counter_enc) {
                encrypted[i] = (byte) ((byte) b ^ data[i++]);
                if (i == encrypted.length)
                    break aes_encrypt;
            }
            bb.clear();
            ctr_counter++;
        }
        return encrypted;
    }
}
