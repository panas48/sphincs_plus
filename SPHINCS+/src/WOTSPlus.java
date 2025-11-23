import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;


//Section 5 (WOTS+)


public class WOTSPlus {

    
//******************************************************************************************************************** */


        //does hash chain for wots+
        public static byte[] chain(byte[] X, int i, int s, byte[] PKSeed, ADRS adrs) throws NoSuchAlgorithmException {
            byte[] tmp = Arrays.copyOf(X, X.length);
            for (int j = i; j < i + s; j++) {
                adrs.setHashAddress(j);
                tmp = HashFunctions.F(PKSeed, adrs, List.of(tmp));
            }
            return tmp;
        }


//******************************************************************************************************************** */


        //makes wots+ public key
        public static byte[] wotsPkGen(byte[] SKSeed, byte[] PKSeed, ADRS adrs) throws NoSuchAlgorithmException {

            ADRS skADRS = new ADRS();
            skADRS.setTypeAndClear(Params.WOTS_PRF);
            skADRS.setKeyPairAddress(adrs.getKeyPairAddress());
    
            List<byte[]> tmp = new ArrayList<>();
            for (int i = 0; i < Params.len; i++) {
                skADRS.setChainAddress(i);
                byte[] sk = HashFunctions.PRF(PKSeed, SKSeed, skADRS);
                adrs.setChainAddress(i);
                tmp.add(chain(sk, 0, Params.w - 1, PKSeed, adrs));
            }

    
            ADRS wotspkADRS = new ADRS();
            wotspkADRS.setTypeAndClear(Params.WOTS_PK);
            wotspkADRS.setKeyPairAddress(adrs.getKeyPairAddress());
    
            return HashFunctions.Tl(PKSeed, wotspkADRS, tmp);
        }


//******************************************************************************************************************** */


        //makes wots+ signature
        public static List<byte[]> wotsSign(byte[] M, byte[] SKSeed, byte[] PKSeed, ADRS adrs) throws NoSuchAlgorithmException {
            int csum = 0;
            int[] msg = HelpFunctions.base_2b(M, Params.lgW, Params.len1);
    
            for (int i = 0; i < Params.len1; i++) {
                csum += Params.w - 1 - msg[i];
            }
            csum <<= 4;
            msg = Arrays.copyOf(msg, Params.len);
            int[] csumBytes = HelpFunctions.base_2b(HelpFunctions.toByte(csum, (int) Math.ceil((Params.len2 * Params.lgW) / 8.0)), Params.lgW, Params.len2);
            System.arraycopy(csumBytes, 0, msg, Params.len1, csumBytes.length);
    
            ADRS skADRS = new ADRS();
            skADRS.setTypeAndClear(Params.WOTS_PRF);
            skADRS.setKeyPairAddress(adrs.getKeyPairAddress());
    
            List<byte[]> sig = new ArrayList<>();
            for (int i = 0; i < Params.len; i++) {
                skADRS.setChainAddress(i);
                byte[] sk = HashFunctions.PRF(PKSeed, SKSeed, skADRS);
                adrs.setChainAddress(i);
                sig.add(chain(sk, 0, msg[i], PKSeed, adrs));
            }
            return sig;
        }
    

//******************************************************************************************************************** */


        //gets wots+ pk from signature
        public static byte[] wotsPkFromSig(List<byte[]> sig, byte[] M, byte[] PKSeed, ADRS adrs) throws NoSuchAlgorithmException {
            int csum = 0;
            int[] msg = HelpFunctions.base_2b(M, Params.lgW, Params.len1);
    
            for (int i = 0; i < Params.len1; i++) {
                csum += Params.w - 1 - msg[i];
            }
            csum <<= 4;
            msg = Arrays.copyOf(msg, Params.len);
            int[] csumBytes = HelpFunctions.base_2b(HelpFunctions.toByte(csum, (int) Math.ceil((Params.len2 * Params.lgW) / 8.0)), Params.lgW, Params.len2);
            System.arraycopy(csumBytes, 0, msg, Params.len1, csumBytes.length);
    
            List<byte[]> tmp = new ArrayList<>();
            for (int i = 0; i < Params.len; i++) {
                adrs.setChainAddress(i);
                tmp.add(chain(sig.get(i), msg[i], Params.w - 1 - msg[i], PKSeed, adrs));
            }
    
            ADRS wotspkADRS = new ADRS();
            wotspkADRS.setTypeAndClear(Params.WOTS_PK);
            wotspkADRS.setKeyPairAddress(adrs.getKeyPairAddress());
    
            return HashFunctions.Tl(PKSeed, wotspkADRS, tmp);
        }


//******************************************************************************************************************** */


}