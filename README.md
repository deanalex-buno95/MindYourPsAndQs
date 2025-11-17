# Mind Your Ps And Qs
Created by Dean Alexander Buno and Lubo Zhou

## 1. Project Description
This is based on a certain picoCTF challenge in 2021: https://youtu.be/-ixz-2gi9r0

The idea of the attack comes with the vulnerability of the RSA cryptosystem, to which for some of the websites, the two prime numbers are either too small or too close to one another.
This makes the factorization of modulo N feasible enough for the attacker to retrieve the private key.
The main goal of this project is to query 10000 websites in parallel and find which ones are vulnerable to this attack.

## 2. Project Goals and Objectives
We will split this project into two parts: Query and Attack

### 2.1 Query
We need to query each of the 10000 websites we will get from Tranco (https://tranco-list.eu/) to do the following:
- Retrieve the certificate.
- Retrieve the public key and pull out:
    - Encryption exponent `e`.
    - Modulus `n`.
- Store the websites' certificate information into a collection (CSV), this will allow us to access the certificates locally without having to get them from the website again.

### 2.2 Attack
To perform the attack, which is to steal the private key of vulnerable websites, we have to perform the following steps:
- Parse through two (or more) different website certificates within the collection of 10K websites, which contains their `e` and `N`.
- We look for the GCD of those website's public key moduli (`n1` and `n2`, `n1` and `n2` being each website's `N`):
    - If `GCD(n1, n2) == 1`:
        - Both moduli are coprime and share no common factors.
        - Base case.
        - No vulnerability found, proceed to check other website certificates (note that it does not mean that neither of these websites are vulnerable, just that it is not discovered yet).
    - If `GCD(n1, n2) > 1`:
        - They share a prime number `p`.
        - Collision case.
        - Vulnerability found, proceed to use RSA algorithm.
- For jackpot cases, we make use of the RSA algorithm to get the following for each certificate:
    - Get the second prime number `q = n / p`.
    - Get the Euler's Totient function `λ(n) = LCM(p - 1, q - 1)`.
    - Get the decryption exponent `d`, where `(d * e) ≡ 1 mod λ(n)`.
    - Retrieve the private key `(d, n)`.

The ones that can be attacked (fit the jackpot case) will be shown in the final output.

## 3. Tech Stack
Python will be used as our main language, and we will make use of two scripts: `query.py` and `attack.py`.

In both cases, we may need to use either `asyncio`, `concurrent`, or `threads` to handle the large sample size.

### 3.1 Query Script
We will extract the certificates in the query script, using the following modules (this is necessary for certificate info collection):
- `ssl`: To create a secure socket connection to the website's host and port and collect the certificate.
- `cryptography`: To parse the certificate and collect the information of `e` and `n`.
- `csv`: To parse through each domain in the websites CSV file and write the certificate information to another CSV file.

### 3.2 Attack Script
We will parse through the certificate information and implement a version of the RSA algorithm that fits our task:
- Python can handle large numbers naturally, though we are not so sure for anything more than the 32-bit integer limit (perhaps we may need to look into BigNum).

## 4. Final Outcome
A collection of websites (out of 10000) that are vulnerable to the attack.
It showcases the need to implement high-quality, high-entropy random number generators when creating keys via the RSA cryptosystem.

