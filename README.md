# Mind Your Ps And Qs
Created by Dean Alexander Buno and Lubo Zhou
Presentation Link (Slides + Video): https://drive.google.com/drive/folders/1mpZi5Y5aO6LrPtLndgJpl1nVJmddI40V?usp=drive_link

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
    - Modulus `n`.
    - Encryption exponent `e`.
- Store the websites' certificate information into a collection (CSV), this will allow us to access the certificates locally without having to get them from the website again.

### 2.2 Attack
To perform the attack, which is to steal the private key of vulnerable websites, we have to perform the following steps:
- Parse through two (or more) different website certificates within the collection of 10K websites, which contains their public key `(n, e)`.
- We look for the GCD of those website's public key moduli (`n1` and `n2` being each website's `n`):
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
    - Get the Euler's Totient function `φ(n) = (p - 1)(q - 1)`.
    - Get the decryption exponent `d`, where `(d * e) ≡ 1 mod φ(n)`.
    - Retrieve the private key `(n, d)`.

The ones that can be attacked (fit the jackpot case) will be shown in the final output.

## 3. Tech Stack
Python will be used as our main language, and we will make use of two scripts: `query.py` and `attack.py`.

Before running any of the scripts, please set up your `.venv` within the repo and install the necessary packages in `requirements.txt`.

```
# Set up virtual environment.
python -m venv .venv

# Activate virtual environment.
.venv\Scripts\activate  # Windows
source .venv/bin/activate  # Linux/macOS

# Install required packages.
pip install -r requirements.txt
```

### 3.1 Query Script
We will extract the certificates with the query script, using the following modules (this is necessary for certificate info collection):
- `asyncio`: To handle asynchronous I/O operations (using semaphores to run tasks concurrently).
- `ssl`: To create the context of the connection to a domain to load the certificates.
- `cryptography`: To parse the certificate and collect the information of `n` and `e`.
- `csv`: To parse through each domain in the websites CSV file and write the certificate information to another CSV file.
- `time`: To check the time it takes to get at least 10K public keys.

First, we set up the domain generator function as an iterator to iterate domains in a stream-like manner, to avoid using the memory to store 1M domains.

Next, we set up the SSL context and a semaphore that limits the number of connections to 500.

Then, we iterate through each domain from the generator function.
This process can fill up a batch up to 5000 domains.
Once there are 5000 domains in a batch, 500 domains at a time will be run concurrently, from loading the certificate to getting the RSA public key (provided that it is available)
Any available domains after running through the batch will be stored in an array and the batch is emptied, repeating the process.
Once the aforementioned array hits the 10000-domain target, the final array is used as input to be written into a CSV file.

To run the script:
```
python query.py
```

### 3.2 Attack Script
We will perform the "Ps and Qs" attack with the attack script, using the following modules ():
- `multiprocessing`: To handle asynchronous mathematical calculations.
- `math`: Use math operations like GCD.
- `collections`: Hash table.
- `itertools`: Generate unique pairs.
- `csv`: To parse through each domain in the websites CSV file and write the certificate information to another CSV file.

First, we load the CSV file's public key information (containing the modulus `n` in hex and public exponent `e` as an integer).

Next, we compute GCD in parallel.

Then, compute `q` of each of the two domains, if they have a shared `p`.

After that, for any `q` output, compute `φ(n)` and private exponent `d`.

Finally, showcase their private key `(n, d)`.

To run the script:
```
python attack.py <input_csv (e.g. rsa_public_keys/rsa_public_keys.csv)>
```

## 4. Final Outcome
Targeted domains (out of 10000) to attack.
It showcases the need to implement high-quality, high-entropy random number generators when creating keys via the RSA cryptosystem.
