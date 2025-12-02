#!/usr/bin/env python3

import sys
import struct


class MD4:
    def __init__(self, message: bytes):
        self.msg = message
        self.length = (len(message) * 8) & 0xffffffffffffffff
        self.msg += b"\x80"
        while (len(self.msg) % 64) != 56:
            self.msg += b"\x00"
        self.msg += struct.pack("<Q", self.length)

        self.A = 0x67452301
        self.B = 0xefcdab89
        self.C = 0x98badcfe
        self.D = 0x10325476

        for i in range(0, len(self.msg), 64):
            self._compress(self.msg[i:i+64])

    def _compress(self, block):
        X = list(struct.unpack("<16I", block))
        A, B, C, D = self.A, self.B, self.C, self.D

        # Round 1
        def F(x,y,z): return (x & y) | (~x & z)
        def G(x,y,z): return (x & y) | (x & z) | (y & z)
        def H(x,y,z): return x ^ y ^ z
        def rol(val, n): return ((val << n) | (val >> (32 - n))) & 0xffffffff

        # Round 1 operations
        S = [3,7,11,19]
        for i in range(16):
            k = i
            if i % 4 == 0:
                A = rol((A + F(B,C,D) + X[k]) & 0xffffffff, S[i % 4])
            elif i % 4 == 1:
                D = rol((D + F(A,B,C) + X[k]) & 0xffffffff, S[i % 4])
            elif i % 4 == 2:
                C = rol((C + F(D,A,B) + X[k]) & 0xffffffff, S[i % 4])
            else:
                B = rol((B + F(C,D,A) + X[k]) & 0xffffffff, S[i % 4])

        # Round 2
        S = [3,5,9,13]
        for i in range(16):
            k = (i % 4) * 4 + (i // 4)
            if i % 4 == 0:
                A = rol((A + G(B,C,D) + X[k] + 0x5a827999) & 0xffffffff, S[i % 4])
            elif i % 4 == 1:
                D = rol((D + G(A,B,C) + X[k] + 0x5a827999) & 0xffffffff, S[i % 4])
            elif i % 4 == 2:
                C = rol((C + G(D,A,B) + X[k] + 0x5a827999) & 0xffffffff, S[i % 4])
            else:
                B = rol((B + G(C,D,A) + X[k] + 0x5a827999) & 0xffffffff, S[i % 4])

        # Round 3
        order = [0,8,4,12,2,10,6,14,1,9,5,13,3,11,7,15]
        S = [3,9,11,15]
        for i in range(16):
            k = order[i]
            if i % 4 == 0:
                A = rol((A + H(B,C,D) + X[k] + 0x6ed9eba1) & 0xffffffff, S[i % 4])
            elif i % 4 == 1:
                D = rol((D + H(A,B,C) + X[k] + 0x6ed9eba1) & 0xffffffff, S[i % 4])
            elif i % 4 == 2:
                C = rol((C + H(D,A,B) + X[k] + 0x6ed9eba1) & 0xffffffff, S[i % 4])
            else:
                B = rol((B + H(C,D,A) + X[k] + 0x6ed9eba1) & 0xffffffff, S[i % 4])

        # Update state
        self.A = (self.A + A) & 0xffffffff
        self.B = (self.B + B) & 0xffffffff
        self.C = (self.C + C) & 0xffffffff
        self.D = (self.D + D) & 0xffffffff

    def digest(self):
        return struct.pack("<4I", self.A, self.B, self.C, self.D)


def ntlm(password: str) -> str:
    data = password.encode("utf-16le")
    return MD4(data).digest().hex().upper()


if __name__ == "__main__":
    print(ntlm(sys.argv[1]))

