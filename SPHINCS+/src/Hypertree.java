import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;


//Section 7 (The SLH-DSA Hypertree)


public class Hypertree {

 
//******************************************************************************************************************** */


    //generates hypertree signature
       public static List<byte[]> htSign(byte[] M, byte[] skSeed, byte[] pkSeed, int idxTree, int idxLeaf) throws NoSuchAlgorithmException {
        
        ADRS adrs = new ADRS();
        adrs.setTreeAddress(idxTree);


        List<byte[]> sigTmp = XMSS.xmssSign(M, skSeed, idxLeaf, pkSeed, adrs);
        List<byte[]> sigHt = new ArrayList<>(sigTmp); 


        byte[] root = XMSS.xmssPkFromSig(idxLeaf, sigTmp, M, pkSeed, adrs);


        for (int j = 1; j < Params.d; j++) {
            idxLeaf = idxTree % (1 << Params.h_);
            idxTree = idxTree >> Params.h_;

            adrs.setLayerAddress(j);
            adrs.setTreeAddress(idxTree);

            sigTmp = XMSS.xmssSign(root, skSeed, idxLeaf, pkSeed, adrs);
            sigHt.addAll(sigTmp);  


            if (j < Params.d - 1) {
                root = XMSS.xmssPkFromSig(idxLeaf, sigTmp, root, pkSeed, adrs);
            }
        }
        return sigHt;
    }


//******************************************************************************************************************** */


        //verifies hypertree signature
        public static boolean htVerify(byte[] M, List<byte[]> sigHt, byte[] pkSeed, int idxTree, int idxLeaf, byte[] pkRoot) throws NoSuchAlgorithmException {
            
            ADRS adrs = new ADRS();
            adrs.setTreeAddress(idxTree);


            List<byte[]> sigTmp = getXMSSSignature(sigHt, 0);
            byte[] node = XMSS.xmssPkFromSig(idxLeaf, sigTmp, M, pkSeed, adrs);


            for (int j = 1; j < Params.d; j++) {
                idxLeaf = idxTree % (1 << Params.h_);
                idxTree = idxTree >> Params.h_;

                adrs.setLayerAddress(j);
                adrs.setTreeAddress(idxTree);


                sigTmp = getXMSSSignature(sigHt, j);
                node = XMSS.xmssPkFromSig(idxLeaf, sigTmp, node, pkSeed, adrs);
            }

            
            System.out.println("Reconstructed Public Key: " + Arrays.toString(node));



            return Arrays.equals(node, pkRoot);
        }


    //******************************************************************************************************************** */

    
        //gets xmss signature part for layer
        public static List<byte[]> getXMSSSignature(List<byte[]> sigHt, int idx) throws NoSuchAlgorithmException {
            int start = idx * (Params.h_ + Params.len);
            int end = (idx + 1) * (Params.h_ + Params.len);
            return sigHt.subList(start, end);
        }

}