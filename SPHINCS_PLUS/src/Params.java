import java.util.HashMap;
import java.util.Map;

public class Params {


//********************************************************************************************************************

//Section 4.2 (Addresses)


    public static int WOTS_HASH; //type for wots+ hash address
    public static int WOTS_PK; //type for wots+ public key address
    public static int TREE;  //type for xmss tree address
    public static int FORS_TREE; //type for fors tree address
    public static int FORS_ROOTS; //type for fors roots address
    public static int WOTS_PRF; //type for wots+ prf address
    public static int FORS_PRF; //type for fors prf address


//********************************************************************************************************************

//Section 11 (Parameter Sets)


    public static int lgW; //log2 of wots base
    public static int w; //wots base

    public static int n; //hash output length in bytes

    public static int h; //full hypertree height
    public static int d; //number of xmss layers
    public static int h_; //xmss subtree height
    public static int a; //fors tree height
    public static int k; //number of fors trees
    public static int m;  //length of message digest

    public static int len1; //wots+ len1 value, message part 
    public static int len2; //wots+ len2 value, checksum part
    public static int len; //wots+ total length


//********************************************************************************************************************


    public static void setupParameterSet(String name) {


        WOTS_HASH = 0;
        WOTS_PK = 1;
        TREE = 2;
        FORS_TREE = 3;
        FORS_ROOTS = 4;
        WOTS_PRF = 5;
        FORS_PRF = 6;


        lgW = 4;
        w = 16; // 2^lgW
        len2 = 3; // Fixed for all parameter sets in SLH-DSA.


//********************************************************************************************************************


//Section 11 (Parameter Sets)
// Parameter selection based on the given parameter set name.
        switch (name) {
            case "SLH-DSA-SHAKE-128s":
                n = 16;
                h = 63;
                d = 7;
                h_ = 9;
                a = 12;
                k = 14;
                m = 30;
                break;

            case "SLH-DSA-SHAKE-128f":
                n = 16;
                h = 66;
                d = 22;
                h_ = 3;
                a = 6;
                k = 33;
                m = 34;
                break;

            case "SLH-DSA-SHAKE-192s":
                n = 24;
                h = 63;
                d = 7;
                h_ = 9;
                a = 14;
                k = 17;
                m = 39;
                break;

            case "SLH-DSA-SHAKE-192f":
                n = 24;
                h = 66;
                d = 22;
                h_ = 3;
                a = 8;
                k = 33;
                m = 42;
                break;

            case "SLH-DSA-SHAKE-256s":
                n = 32;
                h = 64;
                d = 8;
                h_ = 8;
                a = 14;
                k = 22;
                m = 47;
                break;

            case "SLH-DSA-SHAKE-256f":
                n = 32;
                h = 68;
                d = 17;
                h_ = 4;
                a = 9;
                k = 35;
                m = 49;
                break;

////////////////////////////////////////////////


            case "SLH-DSA-SHAKE-24":
                n = 3;    
                h = 4;   
                d = 1;   
                h_ = 4;  
                a = 2;   
                k = 2;   
                m = 2;  
                break;   


            case "SLH-DSA-SHAKE-16":
                n = 2;   
                h = 4;   
                d = 1;   
                h_ = 4;  
                a = 2;   
                k = 2;   
                m = 2;  
                break;                
               

            case "SLH-DSA-SHAKE-8":
                n = 1;   
                h = 4;   
                d = 1;   
                h_ = 4;  
                a = 2;   
                k = 2;   
                m = 2;  
                break;         
                

//for experiment purposes ONLY (experiment 2,3)
////////////////////////////////////////////////

            default:
                System.out.println("Invalid parameter set");
                return;
        }


//********************************************************************************************************************
        

        //calculate len1 and len (len2 has a stable value based on fips205)
        len1 = 2 * n;
        len = len1 + len2;
    }
}
