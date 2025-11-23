This repository is a clean Java implementation of SLH-DSA (SPHINCS+), a stateless hash-based digital signature algorithm. 

It is based exactly on the pseudocode and structure provided in FIPS 205: SLH-DSA, Stateless Hash-Based Digital Signature Standard, published by NIST (U.S. National Institute of Standards and Technology) in 2024 as a standard for post-quantum cryptography. (https://doi.org/10.6028/NIST.FIPS.205) 

Every class is mapped to a section in FIPS 205. Inside each class, you’ll see a comment stating which section of FIPS 205 the logic is based on. This project was created as part of a bachelor thesis at Maastricht University. 

## HOW TO RUN 
----------- 
1) Clone the repository
2) Make sure you have Java 8 or newer, and BouncyCastle in your classpath.
3) Run SPHINCS+/src/Main.java:
   -> You can change the input message by editing - String parameterSet = " ";
   -> You can change the parameter set by editing - byte[] message = " ".getBytes(); 


## OUTPUT 
----------- 
Verify that the given public key matches the reconstructed public key for the corresponding input message. 


## EXPERIMENTS 
----------- 
This repository also contains the code for the three experiments presented in the bachelor thesis.
