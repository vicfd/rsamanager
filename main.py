import sys
from app.rsamanager import RsaManager

if __name__ == '__main__':
    if len(sys.argv) <= 1:
        print(f"The option can't be null")
    elif 'help' == sys.argv[1]:
        print('--------------------')
        print('command list:')
        print('regenerate')
        print('--------------------')
    elif 'regenerate' == sys.argv[1]:
        rsa = RsaManager()
        rsa.regenerate()
    else:
        print(f"Option '{sys.argv[1]}' does not exists")