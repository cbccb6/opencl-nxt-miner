from Crypto.Util import number
import sys
import hashlib
import struct
import copy


class sha256own(object):
    _k = (0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
          0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
          0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
          0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
          0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
          0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
          0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
          0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
          0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
          0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
          0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
          0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
          0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
          0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
          0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
          0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2)
    _h = (0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
          0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19)
    _output_size = 8
    
    blocksize = 1
    block_size = 64
    digest_size = 32
    
    def __init__(self, m=None):        
        self._buffer = ''
        self._counter = 0
        
        if m is not None:
            if type(m) is not str:
                raise TypeError, '%s() argument 1 must be string, not %s' % (self.__class__.__name__, type(m).__name__)
            self.update(m)
        
    def _rotr(self, x, y):
        return ((x >> y) | (x << (32-y))) & 0xFFFFFFFF
                    
    def _sha256_process(self, c):
        w = [0]*64
        w[0:15] = struct.unpack('!16L', c)
        
        for i in range(16, 64):
            s0 = self._rotr(w[i-15], 7) ^ self._rotr(w[i-15], 18) ^ (w[i-15] >> 3)
            s1 = self._rotr(w[i-2], 17) ^ self._rotr(w[i-2], 19) ^ (w[i-2] >> 10)
            w[i] = (w[i-16] + s0 + w[i-7] + s1) & 0xFFFFFFFF
        
        a,b,c,d,e,f,g,h = self._h
        print w
        
        for i in range(64):
            s0 = self._rotr(a, 2) ^ self._rotr(a, 13) ^ self._rotr(a, 22)
            maj = (a & b) ^ (a & c) ^ (b & c)
            t2 = s0 + maj
            s1 = self._rotr(e, 6) ^ self._rotr(e, 11) ^ self._rotr(e, 25)
            ch = (e & f) ^ ((~e) & g)
            t1 = h + s1 + ch + self._k[i] + w[i]
            
            h = g
            g = f
            f = e
            e = (d + t1) & 0xFFFFFFFF
            d = c
            c = b
            b = a
            a = (t1 + t2) & 0xFFFFFFFF
            
        self._h = [(x+y) & 0xFFFFFFFF for x,y in zip(self._h, [a,b,c,d,e,f,g,h])]
        
    def update(self, m):
        if not m:
            return
        if type(m) is not str:
            raise TypeError, '%s() argument 1 must be string, not %s' % (sys._getframe().f_code.co_name, type(m).__name__)
        
        self._buffer += m
        self._counter += len(m)
     
        
        while len(self._buffer) >= 64:
            statedbg=""
            for i in range(0,16):
                pt = self._buffer[i*4:(i+1)*4]
                statedbg += hex(struct.unpack('>I', pt)[0]) + " "
            print statedbg
           
            self._sha256_process(self._buffer[:64])
            self._buffer = self._buffer[64:]


            
    def digest(self):
        mdi = self._counter & 0x3F
        length = struct.pack('!Q', self._counter<<3)
        
        if mdi < 56:
            padlen = 55-mdi
        else:
            padlen = 119-mdi
        
        r = self.copy()
        r.update('\x80'+('\x00'*padlen)+length)


        return ''.join([struct.pack('!L', i) for i in r._h[:self._output_size]])
        
    def hexdigest(self):
        return self.digest().encode('hex')
        
    def copy(self):
        return copy.deepcopy(self)




CURVE_P = (2**255 - 19)
CURVE_A = 121665

def curve25519_monty(x1, z1, x2, z2, qmqp):
    a = (x1 + z1) * (x2 - z2) % CURVE_P
    b = (x1 - z1) * (x2 + z2) % CURVE_P
    x4 = (a + b) * (a + b) % CURVE_P

    e = (a - b) * (a - b) % CURVE_P
    z4 = e * qmqp % CURVE_P

    a = (x1 + z1) * (x1 + z1) % CURVE_P
    b = (x1 - z1) * (x1 - z1) % CURVE_P
    x3 = a * b % CURVE_P

    g = (a - b) % CURVE_P
    h = (a + CURVE_A * g) % CURVE_P
    z3 = (g * h) % CURVE_P

    return x3, z3, x4, z4

def curve25519_mult(n, q):
    nqpqx, nqpqz = q, 1
    nqx, nqz = 1, 0

    for i in range(255, -1, -1):
        if (n >> i) & 1:
            nqpqx,nqpqz,nqx,nqz = curve25519_monty(nqpqx, nqpqz, nqx, nqz, q)
        else:
            nqx,nqz,nqpqx,nqpqz = curve25519_monty(nqx, nqz, nqpqx, nqpqz, q)
    return nqx, nqz

def curve25519(secret, basepoint):
    '''a = ord(secret[0])
    a &= 248
    b = ord(secret[31])
    b &= 127
    b |= 64
    s = chr(a) + secret[1:-1] + chr(b)
    '''
    s = number.bytes_to_long(secret[::-1])
    basepoint = number.bytes_to_long(basepoint[::-1])

    x, z = curve25519_mult(s, basepoint)
    zmone = number.inverse(z, CURVE_P)
    z = x * zmone % CURVE_P
    return number.long_to_bytes(z)[::-1]


if __name__ == "__main__":
   
    arg = sys.argv[1]
    print "org:",arg
    arg_swapped = "".join(reversed([arg[i:i+2] for i in range(0, len(arg), 2)]))
    print "swp:",arg_swapped
    mysecret2 = arg_swapped.decode("hex")
    bp = "09".decode("hex")
    shared2 = curve25519(mysecret2, bp)
    h = sha256own()
    h.update(shared2)
    print "pub:",shared2.encode("hex")
    print "hsh:",h.hexdigest()
    
