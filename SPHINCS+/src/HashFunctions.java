import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.List;

import java.security.Security;
import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.jce.provider.BouncyCastleProvider;


//Section 4.1 (Hash Functions)


public class HashFunctions {
    static {
        Security.addProvider(new BouncyCastleProvider()); //we are using this library for the shake256
    }



//******************************************************************************************************************** */


//shake256 xof, variable output
//hashes all input items into shake256
//handles int, byte[], or lists of those
//unknown types print a warning
//returns output bytes of given length
public static byte[] shake256(Object[] data, int outLen) {
    SHAKEDigest shake256 = new SHAKEDigest(256); // 256-bit capacity

    for (Object item : data) {
        if (item instanceof Integer) {
            byte[] intBytes = HelpFunctions.toByte((Integer) item, 16);
            shake256.update(intBytes, 0, intBytes.length);
        } else if (item instanceof byte[]) {
            byte[] bytes = (byte[]) item;
            shake256.update(bytes, 0, bytes.length);
        } else if (item instanceof List<?>) {
            for (Object elem : (List<?>) item) {
                if (elem instanceof Integer) {
                    byte[] intBytes = HelpFunctions.toByte((Integer) elem, 16);
                    shake256.update(intBytes, 0, intBytes.length);
                } else if (elem instanceof byte[]) {
                    byte[] bytes = (byte[]) elem;
                    shake256.update(bytes, 0, bytes.length);
                } else {
                    System.out.println("shake256: unknown data type in list");
                }
            }
        } else {
            System.out.println("shake256: unknown data type");
        }
    }

    byte[] output = new byte[outLen];
    shake256.doFinal(output, 0, outLen);
    return output;


}


    //******************************************************************************************************************** */


    // H_msg function for digesting message
    public static byte[] H_msg(byte[] R, byte[] pk_seed, byte[] pk_root, List<byte[]> M) throws NoSuchAlgorithmException {
        return shake256(new Object[]{R, pk_seed, pk_root, M}, Params.m);
    }

    // PRF function to get secret values
    public static byte[] PRF(byte[] pk_seed, byte[] sk_seed, ADRS adrs) throws NoSuchAlgorithmException {
        return shake256(new Object[]{pk_seed, adrs.getADRS(), sk_seed}, Params.n);
    }

    // PRF_msg function for randomized message hash
    public static byte[] PRF_msg(byte[] sk_prf, byte[] opt_rand, List<byte[]> M) throws NoSuchAlgorithmException {
        return shake256(new Object[]{sk_prf, opt_rand, M}, Params.n);
    }

    // F function - hash with single input
    public static byte[] F(byte[] pk_seed, ADRS adrs, List<byte[]> M1) throws NoSuchAlgorithmException {
        return shake256(new Object[]{pk_seed, adrs.getADRS(), M1}, Params.n);
    }

    // H function - hash with double input
    public static byte[] H(byte[] pk_seed, ADRS adrs, List<byte[]> M2) throws NoSuchAlgorithmException {
        return shake256(new Object[]{pk_seed, adrs.getADRS(), M2}, Params.n);
    }

    // Tlen function - hash multiple blocks
    public static byte[] Tl(byte[] pk_seed, ADRS adrs, List<byte[]> Ml) throws NoSuchAlgorithmException {
        return shake256(new Object[]{pk_seed, adrs.getADRS(), Ml}, Params.n);
    }

//all these functions are using by default the SHAKE family hash function
    
}


