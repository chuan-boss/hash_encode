class SM3:

    digest_size = 32
    block_size = 64

    def __init__(self):
        self._V = [
            0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600,
            0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e
        ]
        self._unprocessed = b''     # 未处理的消息
        self._length = 0  # 已处理消息字节长度

    def update(self, m: bytes):
        self._unprocessed += m
        # 压缩可成块部分
        for i in range(len(self._unprocessed) // 64):
            self._V = SM3._one_block(self._V, self._unprocessed[i * 64:(i + 1) * 64])
            self._length += 64
        # 记录未成块的部分
        left_length = len(self._unprocessed) % 64
        if left_length > 0:
            self._unprocessed = self._unprocessed[-left_length:]
        else:
            self._unprocessed = b""
        return self

    def digest(self):
        padded = SM3._pad(self._unprocessed, self._length)
        V = self._V
        for i in range(len(padded)//64):
            V = SM3._one_block(V, padded[i*64:(i+1)*64])  # 此处迭代产生了bug。。。已改
        return SM3._words_to_bytes(V)

    def hexdigest(self):
        return self.digest().hex()

    @staticmethod
    def _one_block(V, B):
        """单块处理：扩展后压缩，返回压缩结果"""
        W, WW = SM3._ME(B)
        return SM3._CF(V, W, WW)

    @staticmethod
    def _ME(B):
        """ 消息扩展函数，返回w,w' """
        W = SM3._bytes_to_words(B) + [0]*52
        WW = [0] * 64
        for j in range(16, 68):
            W[j] = SM3._P1(W[j-16] ^ W[j-9] ^ SM3._left_shift(W[j - 3], 15)) \
                   ^ SM3._left_shift(W[j - 13], 7) ^ W[j - 6]
        for j in range(64):
            WW[j] = W[j] ^ W[j+4]
        return W, WW

    @staticmethod
    def _CF(V, W, WW):
        """压缩函数CF，返回V_i+1"""
        A, B, C, D, E, F, G, H = V
        for j in range(64):
            SS1 = SM3._left_shift(
                (SM3._left_shift(A, 12) + E + SM3._left_shift(SM3._T(j), j % 32)) & 0xFFFFFFFF, 7
            )
            SS2 = SS1 ^ SM3._left_shift(A, 12)
            TT1 = (SM3._FF(A, B, C, j) + D + SS2 + WW[j]) & 0xFFFFFFFF
            TT2 = (SM3._GG(E, F, G, j) + H + SS1 + W[j]) & 0xFFFFFFFF
            D = C
            C = SM3._left_shift(B, 9)
            B = A
            A = TT1
            H = G
            G = SM3._left_shift(F, 19)
            F = E
            E = SM3._P0(TT2)
        return [A ^ V[0], B ^ V[1], C ^ V[2], D ^ V[3], E ^ V[4], F ^ V[5], G ^ V[6], H ^ V[7]]

    @staticmethod
    def _pad(message, total_length):
        """比特填充"""
        message_byte_length = total_length + len(message)
        # 消息中填充一个1
        message += b'\x80'
        # 其余填充0
        message += b'\x00' * ((56 - (message_byte_length + 1) % 64) % 64)
        # 填充报文长度
        message += (message_byte_length * 8).to_bytes(8, 'big')
        return message

    @staticmethod
    def _bytes_to_words(b):
        """将字节流转为字列表"""
        res = []
        for i in range(0, len(b), 4):
            res.append(int.from_bytes(b[i:i+4], 'big'))
        return res

    @staticmethod
    def _words_to_bytes(w):
        """将字列表转为字节流"""
        return b"".join(i.to_bytes(4, 'big') for i in w)

    @staticmethod
    def _left_shift(i, shift):
        """32bit循环左移"""
        return (i << shift) & 0xFFFFFFFF | (i >> (32-shift))

    @staticmethod
    def _P0(X):
        return X ^ SM3._left_shift(X, 9) ^ SM3._left_shift(X, 17)

    @staticmethod
    def _P1(X):
        return X ^ SM3._left_shift(X, 15) ^ SM3._left_shift(X, 23)

    @staticmethod
    def _T(j):
        if 0 <= j <= 15:
            return 0x79cc4519
        else:
            return 0x7a879d8a

    @staticmethod
    def _FF(X, Y, Z, j):
        if 0 <= j <= 15:
            return X ^ Y ^ Z
        else:
            return (X & Y) | (X & Z) | (Y & Z)

    @staticmethod
    def _GG(X, Y, Z, j):
        if 0 <= j <= 15:
            return X ^ Y ^ Z
        else:
            return (X & Y) | ((X ^ 0xFFFFFFFF) & Z)


def sm3_hex(m_: bytes) -> str:
    return SM3().update(m_).hexdigest()


if __name__ == "__main__":
    M = input().strip('\n')
    print(sm3_hex(M.encode()))
