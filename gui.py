from utils import *
from os.path import getsize
import time


class BaseGUI(object):
    """
    基本的一个pysimplegui界面类
    """

    def __init__(self):
        # 设置pysimplegui主题，不设置的话就用默认主题
        sg.ChangeLookAndFeel('Purple')
        # 定义2个常量，供下面的layout直接调用，就不用一个个元素来调字体了
        # 字体和字体大小
        self.FONT = ("微软雅黑", 12)
        # 可视化界面上元素的大小
        self.SIZE = (15, 1)
        # 界面布局
        self.layout = [
            # 添加选择文件按钮，使用sg.FileBrowse()
            [sg.Text('*请选择要加密/解密的文件：', font=self.FONT, size=(30, 1))],
            [sg.Input('  ', key="_FILE_", readonly=True,  # readonly=True时不能在图形界面上直接修改该输入框内容
                      size=(36, 1), font=self.FONT),
             sg.FileBrowse(button_text='选择文件', size=(10, 1), font=self.FONT)],
            # 添加选择文件夹按钮，使用
            [sg.Text('*请选择输出文件夹：', font=self.FONT, size=(30, 1))],
            [sg.Input('  ', key="_FOLDER_", readonly=True,
                      size=(36, 1), font=self.FONT),
             sg.FolderBrowse(button_text='选择文件夹', size=(10, 1), font=self.FONT)],
            [sg.Text(' 请输入密钥:', font=self.FONT, size=self.SIZE),
             sg.Input(key='_KEY_', font=self.FONT, size=(30, 1), default_text='randkey')],
            # sg.Btn()是按钮
            [sg.Btn('按我加密！', key='_ENCODE_', font=("微软雅黑", 14), size=(16, 1)),
             sg.Btn('按我解密！', key='_DECODE_', font=("微软雅黑", 14), size=(16, 1))],
            [sg.Text('使用的哈希函数：', font=self.FONT, size=(12, 1)),
             sg.Combo(['md5', 'sha3-224', 'sha3-256', 'sha3-384', 'sha3-512', 'sha2-224',
                       'sha2-256', 'sha2-384', 'sha2-512', 'sha1', 'sm3'], key='_MODE_', default_value='md5')],
            [sg.Text('整块大小(字节)：', font=self.FONT, size=(12, 1)),
             sg.Input(key='_BLOCK_', font=self.FONT, size=(6, 1), default_text='40'),
             sg.Text('左块大小(字节)：', font=self.FONT, size=(12, 1)),
             sg.Input(key='_LEFT_', font=self.FONT, size=(6, 1), default_text='15')],
            # sg.Output()可以在程序运行时，将原本在控制台上显示的内容输出到一个图形文本框里（如print命令的输出）
            [sg.Output(size=(60, 10), font=("微软雅黑", 10), background_color='light gray')],
        ]
        # 创建窗口，引入布局，并进行初始化
        # 创建时，必须要有一个名称，这个名称会显示在窗口上
        self.window = sg.Window('hash-feistel加密工具', layout=self.layout, finalize=True)

    # 窗口持久化
    def run(self):
        hash_mode = {'md5': hash_md5,
                     'sha3-224': hash_sha3_224,
                     'sha3-256': hash_sha3_256,
                     'sha3-384': hash_sha3_384,
                     'sha3-512': hash_sha3_512,
                     'sha2-224': hash_sha2_224,
                     'sha2-256': hash_sha2_256,
                     'sha2-384': hash_sha2_384,
                     'sha2-512': hash_sha2_512,
                     'sha1': hash_sha1,
                     'sm3': hash_sm3}
        # 创建一个事件循环，否则窗口运行一次就会被关闭
        while True:
            # 监控窗口情况
            event, value = self.window.Read()
            if event in ('_ENCODE_', '_DECODE_'):
                filepath = value['_FILE_']
                folderpath = value['_FOLDER_']
                if filepath == '  ' or folderpath == '  ':
                    print("----------------------------------------------------------")
                    print("请输入文件输入和输出路径！")
                    print("----------------------------------------------------------")
                    continue
                block = int(value['_BLOCK_'])
                left = int(value['_LEFT_'])
                if left >= block or left <= 0 or block <= 0:
                    print("----------------------------------------------------------")
                    print("分块非法！")
                    print("----------------------------------------------------------")
                    continue
                key = value['_KEY_']
                mode = value['_MODE_']
                size = getsize(filepath)


                if event == '_DECODE_':
                    size //= 2
                if size > 1024:
                    if size > 1024 * 1024:
                        str_size = '%.2f' % (size / (1024*1024)) + 'MB'
                    else:
                        str_size = '%.2f' % (size / 1024) + 'KB'
                else:
                    str_size = '%d' % size + 'B'
                if event == '_ENCODE_':
                    print("----------------------------------------------------------")
                    print(f"加密的文件是:{filepath}")
                    print(f'文件大小为:{str_size}')
                    print("加密中...")
                    t = self.process(filepath, folderpath, key.encode(), 'encode',
                                     hash_mode=hash_mode[mode], block_len=block, left_len=left)
                    print("加密成功！")
                    print("运行时间：" + str(t) + "秒")
                    print("加密速率：" + "%.3f" % ((size / (1024*1024)) / t) + "MB/s")
                    print(f"输出文件的路径是:{folderpath}/enc.txt")
                    print("----------------------------------------------------------")
                elif filepath[-4:] != '.txt':
                    print("----------------------------------------------------------")
                    print("解密请放入txt文件！")
                    print("----------------------------------------------------------")
                else:
                    print("----------------------------------------------------------")
                    print(f"解密的文件是:{filepath}")
                    print(f'文件大小为:{str_size}')
                    print("解密中...")
                    t = self.process(filepath, folderpath, key.encode(), 'decode',
                                     hash_mode=hash_mode[mode], block_len=block, left_len=left)
                    if t != 0:
                        print("检验通过，解密成功！")
                        print("运行时间：" + str(t) + "秒")
                        print("加密速率：" + "%.3f" % ((size / (1024*1024)) / t) + "MB/s")
                        print(f"输出文件的路径是:{folderpath}/dec")
                    print("---------------------------------------------------------")

            # 如果事件的值为 None，表示点击了右上角的关闭按钮，则会退出窗口循环
            if event is None:
                break
        self.window.close()

    @staticmethod
    def process(input_path: str, out_path: str, key: bytes, mode: str, block_len=None, left_len=None, hash_mode=None):
        # if block_len == None:
        if mode == 'encode':
            with open(input_path, 'rb') as in_file:
                Message = in_file.read()
                in_file.close()
            # 密钥哈希
            key_hash = HASH(key)
            # 明文哈希
            M_hash = HASH(Message)
            time_start = time.clock()
            a = ECB(Message+M_hash, key, block_len, left_len, 'encode', Hash=hash_mode)
            time_end = time.clock()
            out_name = 'enc.txt'
            with open(out_path + '/' + out_name, 'w') as c_out:
                c_out.write(key_hash.hex())
                c_out.write(a.hex())
                c_out.close()
        else:
            with open(input_path, 'r') as in_file:
                Message = in_file.read()
                key_hash = bytes.fromhex(Message[:64])
                in_file.close()
            if HASH(key) != key_hash:
                print("解密失败：密钥出错！")
                return 0
            time_start = time.clock()
            b = ECB(bytes.fromhex(Message[64:]), key, block_len, left_len, 'decode', Hash=hash_mode)
            time_end = time.clock()
            M = b[:-32]
            if HASH(M) != b[-32:]:
                print("解密失败：完整性检验未通过！")
                return 0
            out_name = 'dec'
            with open(out_path + '/' + out_name, 'wb') as c_out:
                c_out.write(M)
                c_out.close()
        return time_end - time_start


if __name__ == '__main__':
    # 实例化后运行
    tablegui = BaseGUI()
    tablegui.run()
