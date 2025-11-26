import csv
from collections import defaultdict

def load_moduli(csv_file):
    data = []
    with open(csv_file, 'r', newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            domain = row['domain'].strip()
            mod_hex = row['modulus_hex'].strip()
            # Clean: strip '0x' prefix if present, lowercase for consistency
            mod_clean = mod_hex.replace('0x', '').lower()
            data.append((domain, mod_clean))
    return data

def find_shared_moduli(data):
    collisions = defaultdict(list)
    for domain, mod in data:
        collisions[mod].append(domain)
    
    # Filter to groups with 2+ domains
    shared = {k: v for k, v in collisions.items() if len(v) > 1}
    return shared


if __name__ == "__main__":
    csv_file = './rsa_public_keys/rsa_public_keys.csv'
    data = load_moduli(csv_file)
    print(f"Loaded {len(data)} domains.")
    
    shared_moduli = find_shared_moduli(data)
    if shared_moduli:
        print("\nShared moduli found (collision groups):")
        for mod_hex, domains in sorted(shared_moduli.items(), key=lambda x: len(x[1]), reverse=True):
            print(f"\nModulus (first 32 chars): {mod_hex[:32]}...")
            print(f"Affected domains: {', '.join(sorted(domains))}")
            print(f"Impact: Private key compromise for {len(domains)} sites!")
    else:
        print("No collisions detected—try scanning more domains next time.")
    
    # Export collisions to simple text file for attack chaining
    # if shared_moduli:
    #     with open('collisions.txt', 'w') as f:
    #         for mod_hex, domains in shared_moduli.items():
    #             f.write(f"{mod_hex}:{','.join(sorted(domains))}\n")
    #     print("\nExported to collisions.txt (format: mod_hex:domain1,domain2) for factoring step.")