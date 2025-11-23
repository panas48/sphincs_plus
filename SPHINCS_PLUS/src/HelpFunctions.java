public class HelpFunctions {


    //computes len2 for wots+
    public static int genLen2(int n, int lgw) {

        int w = (int) Math.pow(2, lgw);
        
        int len1 = (8 * n + lgw - 1) / lgw;
        
        int maxChecksum = len1 * (w - 1);
        
        int len2 = 1;
        
        int capacity = w;
        
        while (capacity <= maxChecksum) {
            len2++;
            capacity *= w;  
        }
        
        return len2;
    }
   

//******************************************************************************************************************** */


    //converts int to byte array
    public static byte[] toByte(int x, int n) {
        byte[] S = new byte[n]; 
        int total = x;
    
        for (int i = 0; i < n; i++) {
            S[n - 1 - i] = (byte) (total & 0xFF);  // Extract least significant byte
            total >>= 8;  // Shift right by 8 bits
        }
        
        return S;
    }
    
    //we are using 0xFF to correctly handle unsigned byte values.
    

 //******************************************************************************************************************** */


    //converts byte array to int
    public static int toInt(byte[] X, int n) {
        int total = 0;
    
        for (int i = 0; i < n; i++) {
            total = 256 * total + (X[i] & 0xFF);  
        }
        
        return total;
    }


//******************************************************************************************************************** */


    //converts bytes to array of base 2^b integers
    public static int[] base_2b(byte[] X, int b, int out_len) {
        int[] baseb = new int[out_len];
        int inIndex = 0;
        int bits = 0;
        int total = 0;
        
        for (int out = 0; out < out_len; out++) {
            while (bits < b) {
                if (inIndex < X.length) {
                    total = (total << 8) + (X[inIndex] & 0xFF);
                    inIndex++;
                    bits += 8;
                } else {
                    break;
                }
            }
            
            bits -= b;
            baseb[out] = (total >> bits) & ((1 << b) - 1);
        }
        
        return baseb;
    }


//******************************************************************************************************************** */


    //joins multiple byte arrays into one
    public static byte[] concatenate(byte[]... arrays) {
        int totalLength = 0;
        for (byte[] array : arrays) {
            totalLength += array.length;
        }

        byte[] result = new byte[totalLength];

        int currentPos = 0;
        for (byte[] array : arrays) {
                System.arraycopy(array, 0, result, currentPos, array.length);
                currentPos += array.length;
            }

        return result;
    }


    //joins two byte arrays
    public static byte[] concat(byte[] a, byte[] b) {
        byte[] result = new byte[a.length + b.length];
        System.arraycopy(a, 0, result, 0, a.length);
        System.arraycopy(b, 0, result, a.length, b.length);
        return result;
    }


//******************************************************************************************************************** */


}