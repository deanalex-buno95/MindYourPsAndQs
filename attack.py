import csv
import math
from collections import defaultdict
from multiprocessing import Pool, cpu_count
from itertools import combinations
import sys

def init_worker(n_lst):  # Sets global in each worker process
    global n_list
    n_list = n_lst

def compute_gcds_chunk(chunk):
    """Compute GCDs for a chunk of pairs; returns (i, j, gcd) for non-trivial ones."""
    results = []
    for i, j in chunk:
        g = math.gcd(n_list[i], n_list[j])
        if 2**512 < g < min(n_list[i], n_list[j]) // 2:  # Threshold: >512-bit, < half n
            print(f"Found GCD for indices {i} and {j}: {g}")
            results.append((i, j, g))
    return results

# Globals for multiprocessing
n_list = []
domain_list = []
e_list = []

def main(input_file):
    global n_list, domain_list, e_list
    # Load CSV data
    data = []
    with open(input_file, 'r', newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            try:
                n = int(row['modulus_hex'], 16)
                e = int(row['public_exponent'])
                if e != 65537: print(f"Oops suprise e={e}")

                data.append({
                    'domain': row['domain'],
                    'n': n,
                    'e': e
                })
            except (ValueError, KeyError) as err:
                print(f"Skipping invalid row for {row.get('domain', 'unknown')}: {err}")
                continue
    
    n_list = [entry['n'] for entry in data]
    domain_list = [entry['domain'] for entry in data]
    e_list = [entry['e'] for entry in data]
    num_keys = len(n_list)
    print(f"Loaded {num_keys} public keys from CSV.")

    # Generate all unique pairs
    pairs = list(combinations(range(num_keys), 2))
    chunk_size = len(pairs) // (cpu_count() * 4) + 1  # Balance load
    chunks = [pairs[i:i + chunk_size] for i in range(0, len(pairs), chunk_size)]

    # Parallel GCD computation
    print("Computing pairwise GCDs in parallel...")
    with Pool(cpu_count(), initializer=init_worker, initargs=(n_list,)) as pool:
        all_gcds = pool.map(compute_gcds_chunk, chunks)
    all_gcds = [item for sublist in all_gcds for item in sublist]  # Flatten

    # Group n's by discovered p (gcd)
    groups = defaultdict(list)
    for i, j, p in all_gcds:
        groups[p].extend([i, j])

    # Dedup and filter groups with >=2 n's
    reused_primes = {p: list(set(indices)) for p, indices in groups.items() if len(set(indices)) >= 2}

    # Compute q's and validate
    print(f"\nFound {len(reused_primes)} reused primes!")
    if not reused_primes:
        print("No reused primes detected (or sample is too small).")
        return

    for p, indices in reused_primes.items():
        print(f"\nReused p: {p}")
        qs = []
        for idx in indices:
            n = n_list[idx]
            q = n // p
            if p * q != n:
                print(f"  WARNING: Invalid factorization for {domain_list[idx]}")
                continue
            qs.append((idx, q))
            print(f"  {domain_list[idx]} (e={e_list[idx]}): q = {q}")
        
        # Compute private d for each
        for idx, q in qs:
            phi = (p - 1) * (q - 1)
            try:
                d = pow(e_list[idx], -1, phi)  # Modular inverse
                print(f"    Private d for {domain_list[idx]}: {d}")
            except ValueError:
                print(f"    Skipping d for {domain_list[idx]}: e not invertible mod phi")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python attack.py <input_csv>")
        sys.exit(1)
    main(sys.argv[1])
    # main("./rsa_public_keys/rsa_public_keys.csv")  # Example hardcoded path for testing