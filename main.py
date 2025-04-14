from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, GT, pair
from charm.toolbox.ABEnc import ABEnc
from functools import reduce

########################################################################
# LSSS for a 2-of-3 threshold policy
########################################################################

class LSSS:
    def __init__(self, group):
        self.group = group

    def create_matrix(self, policy_str):
        """
        2-of-3 threshold for attributes [A, B, C].
        We'll store a simple (3x2) matrix:
            Row 0: [1, 0]  -> attribute A
            Row 1: [1, 1]  -> attribute B
            Row 2: [1, 2]  -> attribute C

        Interpretation: share_i = s + x_i * t, 
        where x_i is row_i[1]. 
        """
        matrix = [
            [1, 0],  # row for A
            [1, 1],  # row for B
            [1, 2]   # row for C
        ]
        attributes = ['A', 'B', 'C']
        return matrix, attributes

    def compute_shares(self, s, matrix):
        """
        Given the matrix from create_matrix(), 
        we pick a random t in ZR, then for each row i:
           share_i = (row_i[0]*s) + (row_i[1]*t).
        Specifically:
           row 0 => x=0 => share_0 = s
           row 1 => x=1 => share_1 = s + t
           row 2 => x=2 => share_2 = s + 2t
        """
        t = self.group.random(ZR)
        shares = {}
        for i, row in enumerate(matrix):
            x_i = row[1]
            share_i = row[0]*s + x_i*t
            shares[i] = share_i
        return shares

    def get_coeffs_2of3(self, matrix, attributes, user_attrs):
        """
        Lagrange interpolation at x=0 to recover s from any 2 shares.

        Row i is at x_i = matrix[i][1].
        If the user has 2 attributes (rows), we do standard 2-point interpolation 
        to get f(0). If they have all 3 attributes, we'll just pick the first 2.

        The standard formula for f(0) given two points (x1, y1), (x2, y2):
           λ1 = (0 - x2)/(x1 - x2),  λ2 = (0 - x1)/(x2 - x1).
        Then f(0) = y1*λ1 + y2*λ2.
        """
        group = self.group
        row_indices = [i for i, attr in enumerate(attributes) if attr in user_attrs]
        if len(row_indices) < 2:
            return {}

        # If user has 3 attributes, just use the first two for interpolation
        if len(row_indices) > 2:
            row_indices = row_indices[:2]

        i1, i2 = row_indices
        x1_int = matrix[i1][1]
        x2_int = matrix[i2][1]

        # Convert x1_int, x2_int into ZR
        x1 = group.init(ZR, x1_int)
        x2 = group.init(ZR, x2_int)

        denom12 = x1 - x2  # in ZR
        denom21 = x2 - x1  # in ZR

        # λ1 = -x2 / (x1 - x2)
        lam1 = -x2 / denom12
        # λ2 = -x1 / (x2 - x1)
        lam2 = -x1 / denom21

        coeffs = {0:0, 1:0, 2:0}  # default zero
        coeffs[i1] = lam1
        coeffs[i2] = lam2
        return coeffs

########################################################################
# CP-ABE skeleton with "toy" revocation checks
########################################################################

class CPabe_Revocation(ABEnc):
    def __init__(self, groupObj):
        ABEnc.__init__(self)
        self.group = groupObj
        self.lsss = LSSS(groupObj)

    def setup(self):
        """
        Create public parameters PP and master key MK.
        We'll keep it simple: 
          - e(g,g)^alpha used to mask the message
          - g^alpha used in user keys
        """
        g = self.group.random(G1)
        h = self.group.random(G2)
        alpha, beta, gamma, delta, eta = self.group.random(ZR, 5)
        
        PP = {
            'g': g,
            'h': h,
            'e_gg_alpha': pair(g, g) ** alpha,  # e(g,g)^alpha
            'eta': eta,
            'H': lambda x: self.group.hash(str(x).encode('utf-8'), ZR)
        }
        MK = {
            'alpha': alpha,
            'beta': beta,
            'gamma': gamma,
            'delta': delta,
            'eta': eta
        }
        return {'PP': PP, 'MK': MK}

    def keygen(self, PP, MK, S, ID, t_u):
        """
        For each attribute in S, the user key = g^(alpha). 
        This is a toy approach, ignoring advanced CP-ABE details.
        """
        K = {}
        for attr in S:
            K[attr] = PP['g'] ** MK['alpha']  # no randomization to keep exponents consistent

        # We'll store time T = h^(gamma) for demonstration
        T = PP['h'] ** MK['gamma']
        return {
            'K': K,       # dict of attribute-> G1
            'T': T,       # G2
            'S': S,       # user attributes
            'ID': ID,     # user ID
            't_u': t_u    # user registration time
        }

    def encrypt(self, PP, MK, M, RL, RA, policy_str, t_c):
        """
        1) LSSS: shares of s 
        2) C_tilde = M * e(g,g)^(alpha*s)
        3) Cy[i] = g^(share_i)
        4) store RL, RA, t_c for toy revocation check
        """
        matrix, attributes = self.lsss.create_matrix(policy_str)

        s = self.group.random(ZR)
        shares = self.lsss.compute_shares(s, matrix)

        # mask the message with e(g,g)^(alpha*s)
        C_tilde = M * (PP['e_gg_alpha'] ** s)

        Cy = {}
        for i, share_i in shares.items():
            Cy[i] = PP['g'] ** share_i

        ciphertext = {
            'C_tilde': C_tilde,
            'Cy': Cy,
            'policy': (matrix, attributes),
            'RL': RL,
            'RA': RA,
            't_c': t_c,
            's': s  # stored for demonstration (insecure)
        }
        return ciphertext

    def decrypt(self, PP, SK, CT):
        """
        1) check revocation
        2) gather Lagrange coeffs for user's attributes
        3) pair( g^(share_i), g^alpha )^λᵢ => e(g,g)^(alpha * share_i * λᵢ)
        4) product => e(g,g)^(alpha * s)
        5) M = C_tilde / that product
        """
        # If revoked, stop
        if self._is_revoked(PP, SK, CT):
            return False

        matrix, attributes = CT['policy']
        coeffs = self.lsss.get_coeffs_2of3(matrix, attributes, SK['S'])
        if not coeffs:
            return False

        # gather partial pairings
        A = self.group.init(GT, 1)
        for i, lam in coeffs.items():
            attr = attributes[i]
            if attr not in SK['K']:
                continue
            pairing_val = pair(CT['Cy'][i], SK['K'][attr])  # e(g^(share_i), g^alpha)
            part = pairing_val ** lam                       # exponent in ZR
            A *= part

        # A = e(g,g)^( alpha*s ) if the Lagrange interpolation is correct
        return CT['C_tilde'] / A

    ########################################################################
    # Revocation helpers
    ########################################################################

    def _revocation_poly(self, PP, RL, RA):
        """
        returns a function P(x) that multiplies (x - H(attr)) for attr in RA.
        We'll skip user IDs in the polynomial and do them in a direct check instead.
        """
        group = self.group
        def P(x):
            val = group.init(ZR, 1)
            for a in RA:
                val *= (x - PP['H'](a))
            return val
        return P

    def _is_revoked(self, PP, SK, CT):
        """
        We revoke the user if:
          1) user time > ciphertext time
          2) user ID is literally in RL
          3) any attribute is in RA => polynomial is zero
        """
        RL, RA, t_c = CT['RL'], CT['RA'], CT['t_c']
        # 1) time-based
        if SK['t_u'] > t_c:
            return True

        # 2) direct ID-based check
        #    If SK['ID'] is in RL, we revoke immediately
        if SK['ID'] in RL:
            return True

        # 3) attribute-based check using polynomial
        #    If P(H(attr))=0 => attribute is revoked
        P = self._revocation_poly(PP, RL, RA)
        for a in SK['S']:
            val = P(PP['H'](a))
            if val == 0:
                return True

        return False

########################################################################
# Main demonstration
########################################################################

def main():
    group = PairingGroup('SS512')
    cpabe = CPabe_Revocation(group)
    params = cpabe.setup()

    # 1) Key generation for user with attributes A, B
    user_attrs = ['A', 'B']
    user_id = 1      # same as the RL we provide
    user_t_u = 8
    sk = cpabe.keygen(params['PP'], params['MK'], user_attrs, user_id, user_t_u)

    # 2) Encrypt a random message under a "2-of-3" policy
    msg = group.random(GT)
    print("Original message:", msg)

    # Revoke user with ID=5, so they should be denied
    ct = cpabe.encrypt(
        PP=params['PP'],
        MK=params['MK'],
        M=msg,
        RL=[5],   # We want to revoke user ID=5
        RA=['D'], # Revoke attribute 'D'
        policy_str="2-of-3",
        t_c=10
    )

    # 3) Decrypt
    result = cpabe.decrypt(params['PP'], sk, ct)
    if result == False:
        print("ACCESS DENIED! (Correctly revoked user with ID=5.)")
    else:
        print("Recovered message:", result)
        if result == msg:
            print("Decryption successful! (User was NOT revoked, check logic.)")
        else:
            print("Wrong plaintext recovered!")

if __name__ == "__main__":
    main()
