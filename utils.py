import PySimpleGUI as sg
import hashlib
from sm3 import SM3


def hash_sha3_512(data: bytes, length) -> int:
    sha3_512 = hashlib.sha3_512()
    sha3_512.update(data)
    return int.from_bytes(sha3_512.digest()[:length], 'big')


def hash_sha3_384(data: bytes, length) -> int:
    sha3_384 = hashlib.sha3_384()
    sha3_384.update(data)
    return int.from_bytes(sha3_384.digest()[:length], 'big')


def hash_sha3_256(data: bytes, length) -> int:
    sha3_256 = hashlib.sha3_256()
    sha3_256.update(data)
    return int.from_bytes(sha3_256.digest()[:length], 'big')


def hash_sha3_224(data: bytes, length) -> int:
    sha3_224 = hashlib.sha3_224()
    sha3_224.update(data)
    return int.from_bytes(sha3_224.digest()[:length], 'big')


def hash_sha2_512(data: bytes, length) -> int:
    sha512 = hashlib.sha512()
    sha512.update(data)
    return int.from_bytes(sha512.digest()[:length], 'big')


def hash_sha2_384(data: bytes, length) -> int:
    sha384 = hashlib.sha384()
    sha384.update(data)
    return int.from_bytes(sha384.digest()[:length], 'big')


def hash_sha2_256(data: bytes, length) -> int:
    sha256 = hashlib.sha256()
    sha256.update(data)
    return int.from_bytes(sha256.digest()[:length], 'big')


def hash_sha2_224(data: bytes, length) -> int:
    sha224 = hashlib.sha224()
    sha224.update(data)
    return int.from_bytes(sha224.digest()[:length], 'big')


def hash_sm3(data: bytes, length) -> int:
    return int.from_bytes(SM3().update(data).digest()[:length], 'big')


def hash_md5(data: bytes, length) -> int:
    md5 = hashlib.md5()
    md5.update(data)
    return int.from_bytes(md5.digest()[:length], 'big')


def HASH(data: bytes) -> bytes:
    h = hashlib.sha3_256()
    h.update(data)
    return h.digest()


def hash_sha1(data: bytes, length) -> int:
    sha1 = hashlib.sha1()
    sha1.update(data)
    return int.from_bytes(sha1.digest()[:length], 'big')


def encode(M: bytes, K: bytes, L_len: int, R_len: int, Hash, enc_times=1, round_times=3) -> bytes:
    L = int.from_bytes(M[:L_len], 'big')
    R = int.from_bytes(M[-R_len:], 'big')
    for i in range(enc_times):
        for j in range(round_times):
            L, R = R, L ^ Hash(K + R.to_bytes(R_len, 'big'), L_len)
            L_len, R_len = R_len, L_len
        L, R = R.to_bytes(R_len, 'big'), L.to_bytes(L_len, 'big')
    return L + R


def padding(_data: bytes, _block_len) -> bytes:
    _len = _block_len - len(_data)
    return _data + (_len * _len.to_bytes(1, 'big'))


def de_padding(_data: bytes) -> bytes:
    _len = len(_data) - _data[-1]
    return _data[:_len]


def ECB(M: bytes, key: bytes, block_len: int, left_len: int, mode: str, Hash=hash_md5) -> bytes:
    """
    :param Hash: 用的哈希函数
    :param M: the message of any length
    :param key: the key of any length
    :param block_len: 按字节计算的分组块大小，不大于两倍哈希函数输出块大小
    :param left_len: 按字节计算的左边块大小，小于block_len
    :param mode: literal['encode', 'decode']
    :return:
    """
    cnt = len(M) // block_len
    out = bytearray(len(M) - len(M) % block_len)
    count = range(cnt)
    for i, item in enumerate(count):
        if (i & 16383) == 0:
            sg.one_line_progress_meter('实时进度条', i + 1, len(count))
        out[i * block_len:(i + 1) * block_len] = encode(M[block_len * i:block_len * (i + 1)],
                                                        key, left_len, block_len - left_len, Hash)
    sg.one_line_progress_meter('实时进度条', len(count), len(count))
    # for i in range(cnt):
    #     out[i * block_len:(i + 1) * block_len] = encode(M[block_len * i:block_len * (i + 1)],
    #                                                     key, left_len, block_len - left_len, Hash)
    #     if (i & 0b1111111) == 0:
    #         print("\r", end="")
    #         _k = ((i * 100) // cnt // 2)
    #         print("进度: {}%: ".format((i * 100) // cnt), '[' + "▓" * _k + '-' * (50 - _k) + ']', end="")
    #         sys.stdout.flush()
    # print("\r", end="")
    # print("进度: {}%: ".format(100), '[' + "▓" * 50 + ']', end="")
    # sys.stdout.flush()
    if mode == 'encode':
        last_block = M[-(len(M) % block_len):] if len(M) % block_len != 0 else b''
        out += encode(padding(last_block, block_len), key, left_len, block_len - left_len, Hash)
        # print("\nencode completed")
    elif mode == 'decode':
        out = de_padding(out)
        # print("\ndecode completed")
    return out


if __name__ == '__main__':
    # input_path = './sm3.py'
    input_path = 'F:/vedio/录制/操作系统期末复习2.mkv'
    out_path = './output/'
    with open(input_path, 'rb') as in_file:
        Message = in_file.read()
        in_file.close()
    key = "key".encode()

    a = ECB(Message, key, 54, 30, 'encode')
    with open(out_path + 'ciphertext.txt', 'w') as c_out:
        c_out.write(a.hex())
        c_out.close()
    with open(out_path + 'ciphertext.txt', 'r') as c_in:
        x = c_in.read()
        c_in.close()

    b = ECB(bytes.fromhex(x), key, 54, 30, 'decode')
    with open(out_path + 'recovered.txt', 'wb') as m_out:
        m_out.write(b)
        m_out.close()
