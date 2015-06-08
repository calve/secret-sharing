from secretsharing import SecretSharer
import random


n = 10
k = 4


def main():
    """
    Generate a 128 bits AES key, and split it in parts
    """
    print("Generating randomness")
    random_bytes = format(random.SystemRandom().getrandbits(128), 'x')
    print("Key : %s" % str(random_bytes))
    shares, g, p, commitments = SecretSharer.split_verifiable_secret(str(random_bytes), k, n)
    print("g : %s" % g)
    print("p : %s" % p)
    print()
    print("Commitments (%d) (public):" % len(commitments))
    print('\n'.join([str(c) for c in commitments]))
    print()
    # print "Parts (g**secret mod p) (%d) (public):" % len(parts)
    # print '\n'.join([str(part) for part in parts])
    # print
    print("Secrets (%d) (private, one by user):" % len(shares))
    print('\n'.join([str(s)+" <=> "+str(int(s[2:], 16)) for s in shares]))
    print()
    print("now verify")
    for share in shares:
        print((SecretSharer.verify(share, commitments, g, p)))
    print()
    # print "verify commitments"
    # for part in parts:
    #     print(SecretSharer.verify_commitment(part, g, p, k, commitments))

if __name__ == "__main__":
    main()
