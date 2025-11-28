from collections import Counter
import re

def parse_collisions(file_path):
    collisions = {}
    with open(file_path, 'r') as f:
        for line in f:
            if ':' in line:
                mod, doms_str = line.strip().split(':', 1)
                domains = [d.strip() for d in doms_str.split(',')]
                collisions[mod] = domains
    return collisions

def cluster_by_company(domains):
    roots = []
    for d in domains:
        # root = part before first '.' (e.g., 'amazon.co.uk' → 'amazon')
        root_match = re.match(r'^([a-zA-Z0-9-]+)\.', d)
        root = root_match.group(1).lower() if root_match else d.lower()
        roots.append(root)
    unique_roots = set(roots)
    root_counts = Counter(roots)
    is_intra = len(unique_roots) == 1
    return unique_roots, root_counts, is_intra

# Analyze and report
if __name__ == "__main__":
    file_path = 'collisions.txt'
    collisions = parse_collisions(file_path)
    
    print("| Modulus Prefix | Domains Count | Unique Roots | Intra-Company? | Example Roots |")
    print("|----------------|---------------|--------------|----------------|---------------|")
    
    for mod, domains in sorted(collisions.items(), key=lambda x: len(x[1]), reverse=True):
        unique_roots, root_counts, intra = cluster_by_company(domains)
        root_ex = ', '.join(sorted(root_counts.keys())[:3]) + ('...' if len(root_counts) > 3 else '')
        print(f"| {mod[:16]}... | {len(domains)} | {len(unique_roots)} | {'Yes' if intra else 'No!'} | {root_ex} |")