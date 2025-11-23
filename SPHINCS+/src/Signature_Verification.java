import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;


public class Signature_Verification {


//********************************************************************************************************************


    //verifies slh-dsa signature
    public static boolean slhVerify(byte[] M, List<byte[]> SIG, List<byte[]> ctx, Object[] PK) throws NoSuchAlgorithmException {

        if (ctx.size() > 255) {
            return false;
        }

        byte[] MPrime = HelpFunctions.concatenate(
            HelpFunctions.toByte(0, 1),
            HelpFunctions.toByte(ctx.size(), 1),
            HelpFunctions.concatenate(ctx.toArray(new byte[0][])),
            M
        );
    

        return Internal_Functions.slhVerifyInternal(List.of(MPrime), SIG, PK);
    }


//********************************************************************************************************************


//NOT USED IN THE FINAL CODE
    public static boolean hashSlhVerify(byte[] M, List<byte[]> SIG, List<byte[]> ctx, String PH, Object[] PK) throws NoSuchAlgorithmException {
        if (ctx.size() > 255) {
            return false;
        }

        byte[] PHM;
        byte[] OID;

        // Pre-hash the message
        try {
            switch (PH) {
                case "SHA-256":
                    //OID = HelpFunctions.toByte(0x0609608648016503040201L, 11);
                    OID = new byte[]{0x06, 0x09, 0x60, (byte) 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01};
                    PHM = MessageDigest.getInstance("SHA-256").digest(M);
                    break;
                // case "SHA-512":
                //     OID = toByte(0x0609608648016503040203L, 11);
                //     PHM = MessageDigest.getInstance("SHA-512").digest(M);
                //     break;
                // case "SHAKE128":
                //     OID = toByte(0x060960864801650304020BL, 11);
                //     PHM = shake128(M, 256);
                //     break;
                // case "SHAKE256":
                //     OID = toByte(0x060960864801650304020CL, 11);
                //     PHM = shake256(M, 512);
                //     break;
                default:
                    // Handle other approved hash functions or XOFs
                    throw new UnsupportedOperationException("Unsupported pre-hash function");
            }
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Hash algorithm not available", e);
        }


        byte[] MPrime = HelpFunctions.concatenate(
            HelpFunctions.toByte(1, 1),
            HelpFunctions.toByte(ctx.size(), 1),
            HelpFunctions.concatenate(ctx.toArray(new byte[0][])),
            OID,
            PHM
        );
    

        return Internal_Functions.slhVerifyInternal(List.of(MPrime), SIG, PK);
    }

}