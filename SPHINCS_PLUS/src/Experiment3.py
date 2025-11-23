
from qiskit import QuantumCircuit, transpile
from qiskit_aer import AerSimulator
from qiskit.visualization import plot_histogram
import matplotlib.pyplot as plt
import numpy as np
import jpype
import jpype.imports
from jpype.types import *
import time


#RESEARCH QUESTION 3
#How effectively can a hybrid Grover-based simulation illustrate the potential of future quantum attacks on SPHINCS+ via XMSS authentication path forgery?

################################################################################################################333


#JVM - connect python and java to find classically a correct value for the attack
jpype.startJVM(classpath=["./class", "libs/bcprov-jdk18on-1.79.jar"])
XMSS = jpype.JClass("XMSS")
Params = jpype.JClass("Params")
ADRS = jpype.JClass("ADRS")
ArrayList = jpype.JClass("java.util.ArrayList")


################################################################################################################333


#Initialization
class XMSSVerifier:
    def __init__(self):
        Params.setupParameterSet("SLH-DSA-SHAKE-8")
        self.adrs = ADRS()
        self.message = JArray(JByte)([72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100]) # = Hello World
        self.originalPk = JArray(JByte)([20])
        self.attackerPkSeed = JArray(JByte)([-47])

        self.signature_base = ArrayList()
        for val in [-82, -57, -10, 45, 116, -110, -8, -80]:
            self.signature_base.add(JArray(JByte)([val]))
        self.signature_base.add(JArray(JByte)([0]))  # Placeholder
    
        
################################################################################################################333


#verify classically
    def verify_candidate(self, candidate):
        java_byte = ((candidate + 128) % 256) - 128
        temp_sig = ArrayList(self.signature_base)
        temp_sig.set(len(temp_sig)-1, JArray(JByte)([java_byte]))
        try:
            derived_pk = XMSS.xmssPkFromSig(
                0, temp_sig, self.message, self.attackerPkSeed, self.adrs
            )
            return list(derived_pk) == list(self.originalPk)
        except:
            return False
        
        
################################################################################################################333


#quantum circuit
def create_grover_circuit(solution_guess, n_qubits=8, iterations=12):
    
    #create a quantum circuit with n qubits and n classical bits for measurement
    qc = QuantumCircuit(n_qubits, n_qubits)
    
    #apply hadamard to all qubits to create an equal superposition over 2^n states
    qc.h(range(n_qubits))
    
    
    for _ in range(iterations):
        
        
        #############################
        
        
        # Oracle
        for qubit in range(n_qubits):
            
            #flip all bits that are zero in the target solution to prepare for controlled flip
            if not (solution_guess >> qubit) & 1:
                qc.x(qubit)
                
                
        #apply multi-controlled NOT gate to flip the target state's phase
        qc.h(n_qubits-1) #put target in x-basis
        qc.mcx(list(range(n_qubits-1)), n_qubits-1) #controlled flip
        qc.h(n_qubits-1) #return to original basis
        
        
        #undo the flips we did earlier (to clean up the oracle)
        for qubit in range(n_qubits):
            if not (solution_guess >> qubit) & 1:
                qc.x(qubit)
             
        
        #############################
        
                
        # Diffuser
        for qubit in range(n_qubits):
            qc.h(qubit) #transform to x-basis
        for qubit in range(n_qubits):
            qc.x(qubit) #invert around zero
            
        qc.h(n_qubits-1)
        qc.mcx(list(range(n_qubits-1)), n_qubits-1)
        qc.h(n_qubits-1)
        
        for qubit in range(n_qubits):
            qc.x(qubit) #invert back
        for qubit in range(n_qubits):
            qc.h(qubit) #return to original basis
            
            
        #############################
            
    #measure all qubits to observe the result
    qc.measure(range(n_qubits), range(n_qubits))
    
    
    return qc


################################################################################################################


def run_hybrid_attack():
    verifier = XMSSVerifier()
    simulator = AerSimulator()
    iterations = 12  


    #find classically
    for x in range(256):
        print(f"\nChecking x = {x}")
        if verifier.verify_candidate(x):
            print(f"Candidate {x} is valid!\n")

            #run quantum circuit
            qc = create_grover_circuit(x, iterations=iterations)
            compiled = transpile(qc, simulator)
            result = simulator.run(compiled, shots=1000).result()

            #histogram
            counts = result.get_counts(compiled)
            print("Quantum measurement results:")
            print(counts)
            plot_histogram(counts)
            plt.title(f"Grover Output (Marked x = {x})")
            plt.xlabel("Measured Value")
            plt.ylabel("Counts")
            plt.show()


            #metrics 
            width = qc.num_qubits
            depth = qc.depth()
            logical_qubit_cycles = width * depth
            t_gate_count = qc.count_ops().get('t', 0)
            estimated_physical_qubits = width * 1000
            runtime_seconds = (depth * 200e-9)
            runtime_years = runtime_seconds / (60 * 60 * 24 * 365)

            print("\nQuantum Resource Metrics:")
            print(f"• Grover Iterations        : {iterations}")
            print(f"• Logical Qubits (Width)   : {width}")
            print(f"• Surface Code Cycles (Depth): {depth}")
            print(f"• Logical-Qubit-Cycles     : {logical_qubit_cycles}")
            print(f"• T-Gates Used             : {t_gate_count}")
            print(f"• Estimated Physical Qubits: {estimated_physical_qubits}")
            print(f"• Runtime Estimate         : {runtime_seconds:.6f} seconds ({runtime_years:.2e} years)")

            print(f"\nMeasured top value: {max(counts, key=counts.get)}")
            return x

    print("No valid AUTH[h-1] found in 8-bit space.")
    return None



################################################################################################################


#main function
if __name__ == "__main__":
    result = run_hybrid_attack()
    if result is not None:
        print(f"\nAttack successful! Found AUTH[h-1] = {result}")
    else:
        print("\nAttack failed. No solution found.")

    # Shutdown JVM
    jpype.shutdownJVM()


################################################################################################################
#OUTPUT
#WE HARDCODED THE INPUTS SO THE CORRECT VALUE IS KNOWN (10) - EXPERIMENT 2 CODE WAS USED


# Checking x = 0

# Checking x = 1

# Checking x = 2

# Checking x = 3

# Checking x = 4

# Checking x = 5

# Checking x = 6

# Checking x = 7

# Checking x = 8

# Checking x = 9

# Checking x = 10
# Candidate 10 is valid!

# Quantum measurement results:
# {'00001010': 1000}

# Quantum Resource Metrics:
# • Grover Iterations        : 12
# • Logical Qubits (Width)   : 8
# • Surface Code Cycles (Depth): 146
# • Logical-Qubit-Cycles     : 1168
# • T-Gates Used             : 0
# • Estimated Physical Qubits: 8000
# • Runtime Estimate         : 0.000029 seconds (9.26 * e^-13 years)

# Measured top value: 00001010

# Attack successful! Found AUTH[h-1] = 10