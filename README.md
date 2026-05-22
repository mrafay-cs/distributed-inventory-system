# Distributed Inventory System

A secure distributed inventory ledger system built in Python to simulate how businesses can maintain trusted and consistent inventory records across multiple validator nodes.

## Overview

This project explores how distributed validation and cryptographic verification can improve inventory consistency, authenticity, and secure record retrieval across multiple warehouse or inventory locations.

The system implements:

- RSA digital signatures
- Proof of Authority consensus
- distributed validator nodes
- tampered record detection
- secure multi-signature query retrieval
- encrypted response delivery

## Technologies Used

- Python
- JSON
- RSA Cryptography
- MD5 Hashing
- Proof of Authority Consensus
- VS Code

## System Architecture

The system simulates four distributed inventory validator nodes:

- Inventory A
- Inventory B
- Inventory C
- Inventory D

Each node maintains:
- its own local inventory database
- independent validator behaviour
- cryptographic key parameters

## Record Validation Workflow

Record Submission  
→ Message Hashing  
→ RSA Signature Generation  
→ Signature Verification  
→ Proof of Authority Consensus  
→ Distributed Record Storage

## Secure Retrieval Workflow

Query Submission  
→ Multi-Signature Generation  
→ Collective Verification  
→ Consensus Approval  
→ Encrypted Response Delivery  
→ Secure Query Recovery

## Repository Structure

```bash
core/
    record_validation_engine.py
    secure_query_retrieval.py

data/
    inventory records
    cryptographic parameter files
    PKG keys
    procurement officer keys
```

## Running the Project

```bash
python core/record_validation_engine.py
```

```bash
python core/secure_query_retrieval.py
```

## Future Improvements

- real distributed networking
- database integration
- cloud deployment
- web-based dashboard
- stronger hashing algorithms
