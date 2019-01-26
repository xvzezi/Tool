import getpass
import json
import os
import uuid
from binascii import b2a_hex, a2b_hex

from Crypto.Cipher import AES


def get_mac_address():
    mac = uuid.UUID(int=uuid.getnode()).hex[-12:].upper()
    # return '%s:%s:%s:%s:%s:%s' % (mac[0:2],mac[2:4],mac[4:6],mac[6:8],mac[8:10],mac[10:])
    return ":".join([mac[e:e + 2] for e in range(0, 11, 2)])


def reg_a_pwd(name):
    while True:
        pwd = getpass.getpass('Input your ' + name + ' password(no more than 16):')
        if len(pwd) == 0 or len(pwd) > 16:
            continue
        pwd2 = getpass.getpass('Input your password again:')
        if pwd == pwd2:
            pwd = pwd + (16 - len(pwd)) * 'q'
            return pwd


def line():
    print('--------------------')


class XPwdMaster:
    """
    Password Master
    Step Func:
        1. master.ready_to_load()       # preload the data
        2. master.ready_to_serve()      # serve the user
        3. master.clean_to_end()        # quit
    Or could call in 1 step:
        1. master.boot()
    Other helper func:
        1. dump_to_file
            store the basic format and pwds into 'pwd.dict'
        2. new_env
            no 'pwd.dict' found and create a new working field
        3. check_meta
            check the existing meta file
    """

    def __init__(self):
        # ---------------
        # Basic Format -> Into File
        self.info = 'XPwdMaster v1 Qinx'
        self.user = ''  # username
        self.type = 0  # 0 for mac; 1 for sec
        # Live Format -> Run Time
        self.mac = get_mac_address()[:-1]  # location identifier
        self.key = ''  # get from the input
        self.mode = AES.MODE_CBC  # CBC encrypt mode
        self.sec = ''  # second key
        self.pwds = {}

    def encrypt(self, text, mode=None):
        tar = ''
        if self.type == 0:
            tar = self.mac
        else:
            tar = self.sec

        if mode is not None:
            tar = 'Qin Loves Xvzezi'

        cryptor = AES.new(self.key, self.mode, tar)

        # complement for test to 16 times
        length = 16
        count = len(text)
        add = length - (count % length)
        text = text + ('\0' * add)
        tartext = cryptor.encrypt(text)
        return b2a_hex(tartext)

    def decrypt(self, text, mode=None):
        tar = ''
        if self.type == 0:
            tar = self.mac
        else:
            tar = self.sec

        if mode is not None:
            tar = 'Qin Loves Xvzezi'

        cryptor = AES.new(self.key, self.mode, tar)

        tartext = cryptor.decrypt(a2b_hex(text))
        return tartext.decode().rstrip('\0')

    def boot(self):
        self.ready_to_load()
        self.ready_to_serve()
        self.clean_to_end()

    def ready_to_load(self):
        # check if the init mode 
        if not os.path.exists('pwd.dict'):
            self.new_env()

        # Get passwords from the file
        with open('pwd.dict', 'rb') as tar:
            key = getpass.getpass('Base Key:')
            if len(key) == 0 or len(key) > 16:
                print('More than 16 chars')
                exit(1)
            self.key = key + (16 - len(key)) * 'q'
            en = tar.readline()
            if en is None or len(en) == 0:
                print('Empty File')
                exit(2)
            de = self.decrypt(en, mode={})
            self.meta = json.loads(de)
            if not self.check_meta():
                line()
                print('Error:', 'Pwd.dict wrong format')
                exit(1)
            else:
                line()
                print('welcome', self.user)

    def ready_to_serve(self):
        # pre process
        center = {
            'help': self.help,
            'all': self.all,
            'web': self.web,
            'add': self.add,
            'remove': self.remove
        }

        # ready
        line()
        print('Serving...')
        while True:
            cmd = input('> ').split(' ')
            if cmd[0] == 'quit':
                break
            tar = center.get(cmd[0])
            if tar is not None:
                tar(cmd)
            else:
                print('No Such cmd. Type Help to see more')

        return

    def clean_to_end(self):
        self.dump_to_file()
        return

    def dump_to_file(self):
        meta = {
            'info': self.info,
            'type': self.type,
            'user': self.user,
            'pwds': self.pwds
        }
        # encrypt
        tar = json.dumps(meta)
        en = self.encrypt(tar, mode={})
        with open('pwd.dict', 'wb') as fp:
            fp.write(en)

        return

    def new_env(self):
        # init basic user information 
        line()  # username
        print('New environment detected~')
        name = input('Welcome, Tell me your name:')
        self.user = name.split(' ')[0]
        print('Your Name is', self.user)
        print('Please remember')

        line()  # base pwd
        self.key = reg_a_pwd('base')

        line()  # get type
        print('U r gonna choose a type:')
        print(' - mac : password can only be decryted on the same mac')
        print(' - sec : need a second level password to decrypt')
        done = False
        while not done:
            raw = input('Please input the type: ')
            if raw == 'mac':
                self.type = 0
                done = True
            elif raw == 'sec':
                self.type = 1
                self.sec = reg_a_pwd('second')
                done = True
            else:
                print('Bad Type! Try again')

        self.pwds = {}
        line()  # write into file 
        self.dump_to_file()

        return

    def check_meta(self):
        # version check
        if not self.meta.get('info') == self.info:
            return False
            # type check
        if self.meta.get('type') is None:
            return False
        else:
            self.type = self.meta.get('type')
            if not (self.type == 1 or self.type == 0):
                return False
        if self.type == 1:
            sec = getpass.getpass('Require Sec Level Pass:')
            if len(sec) == 0 or len(sec) > 16:
                print('More than 16 chars')
                exit(3)
            self.sec = sec + (16 - len(sec)) * 'q'
        # user check
        if self.meta.get('user') is None:
            return False
        else:
            self.user = self.meta.get('user')
        # fetch the dict
        if self.meta.get('pwds') is None:
            self.pwds = {}
        else:
            self.pwds = self.meta.get('pwds')
        return True

        # func used in ready to serve

    def help(self, args):
        print('Module: XPasswordMaster')
        print('Version: v1.0')
        print('By: Sturmfy')
        line()
        print('> help :', 'print these texts')
        print('> all :', 'print all password onto the screen.',
              'pwd should be specified when using this cmd.',
              'if pwd has been set by "pwd", then the args after "all" are ignored',
              '(the same for "web" "add" "remove")')
        print('> web website :', 'get specified website\'s pwd')
        print('> add website name pwd :', 'add a new account, base key should be given before using this cmd')
        print('> remove website [name] pwd1:', 'UNIMPLE. remove accounts, base key should be checked again')
        return

    def print_list(self, website, tar):
        for name, pwd in tar:
            de_name = self.decrypt(name)
            de_pwd = self.decrypt(pwd)
            print(website + '\t\t\t\t',
                  de_name + '\t\t',
                  de_pwd)

    def all(self, args):
        print('website\t\t\t\t', 'name\t\t', 'pwd')
        for website in self.pwds:
            self.print_list(website, self.pwds[website])
        return

    def web(self, args):
        if len(args) <= 1:
            return
        tars = self.pwds.get(args[1])
        if tars is None:
            print('No Such Website')
            return
        print('website\t\t\t\t', 'name\t\t', 'pwd')
        self.print_list(args[1], tars)
        return

    def add(self, args):
        if not len(args) == 4:
            print('Wrong Format')
            return
        website = args[1]
        en_name = self.encrypt(args[2]).decode()
        en_pwd = self.encrypt(args[3]).decode()
        if self.pwds.get(website) is not None:
            self.pwds.get(website).append((en_name, en_pwd))
        else:
            self.pwds[website] = [(en_name, en_pwd)]
        print('Done')
        return

    def remove(self, args):
        print('unimplemented')
        return


def test():
    print(len(get_mac_address()), get_mac_address()[:-1])
    return


def main():
    tar = XPwdMaster()
    tar.boot()
    return


if __name__ == '__main__':
    main()
