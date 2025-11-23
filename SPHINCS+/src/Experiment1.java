import java.util.*;
import java.io.*;

public class Experiment1 {

//RESEARCH QUESTION 1
//How do the choice of hash functions and their parameter settings influence the time and memory efficiency of SPHINCS+?



    //list of all parameter sets to test
    static String[] parameterSets = {
        "SLH-DSA-SHAKE-128s",
        "SLH-DSA-SHAKE-128f",
        "SLH-DSA-SHAKE-192s",
        "SLH-DSA-SHAKE-192f",
        "SLH-DSA-SHAKE-256s",
        "SLH-DSA-SHAKE-256f"
    };

    public static void main(String[] args) {
        try {

            //message to be signed
            byte[] message = "Hello World".getBytes();


            //how many times to repeat each test - this line sets how many times each operation is repeated
            int runs = 100;


            //run tests for each parameter set
            for (String parameterSet : parameterSets) {
                Params.setupParameterSet(parameterSet);
                System.out.println(parameterSet);


                //measure time taken to generate keys
                long keygenTime = 0;
                Object[] SK = null, PK = null;
                for (int i = 0; i < runs; i++) {
                    long start = System.nanoTime();
                    Object[] keys = External_Functions.slhKeygen();
                    keygenTime += (System.nanoTime() - start);
                    if (i == 0) { // keep for reuse
                        SK = (Object[]) keys[0];
                        PK = (Object[]) keys[1];
                    }
                }
                System.out.println("Average KeyGen Time (ms): " + (keygenTime / runs) / 1e6);



                //measure time taken to sign a message
                long signTime = 0;
                List<byte[]> signature = null;
                for (int i = 0; i < runs; i++) {
                    long start = System.nanoTime();
                    signature = External_Functions.slhSign(message, new ArrayList<>(), SK);
                    signTime += (System.nanoTime() - start);
                }
                System.out.println("Average Sign Time (ms): " + (signTime / runs) / 1e6);



                //calculate total signature size in bytes
                int sigSize = signature.stream().mapToInt(s -> s.length).sum();
                System.out.println("Signature Size (bytes): " + sigSize);



                //measure verification time and memory usage
                long verifyTime = 0;
                long memoryUsage = 0;
                Runtime runtime = Runtime.getRuntime();

                for (int i = 0; i < runs; i++) {
                    System.gc(); //try to clean up memory before each run
                    long beforeUsedMem = runtime.totalMemory() - runtime.freeMemory();

                    long start = System.nanoTime();
                    boolean valid = Signature_Verification.slhVerify(message, signature, new ArrayList<>(), PK);
                    verifyTime += (System.nanoTime() - start);

                    long afterUsedMem = runtime.totalMemory() - runtime.freeMemory();
                    memoryUsage += (afterUsedMem - beforeUsedMem);

                    if (!valid) System.out.println("Signature Invalid (Run " + i + ")");
                }
                System.out.println("Average Verify Time (ms): " + (verifyTime / runs) / 1e6);
                System.out.println("Peak Memory Usage during Verify (bytes): " + (memoryUsage / runs));

                //key sizes
                System.out.println("Secret Key Size (bytes): " + (Params.n * 3 + Params.n));
                System.out.println("Public Key Size (bytes): " + (Params.n * 2));
                System.out.println();
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}


//********************************************************************************************************************
//OUTPUT
//When you run this code, it performs 100 independent runs for each SPHINCS+ parameter set