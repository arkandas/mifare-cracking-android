# Parse card data from .mdf dumps

from sys import argv
from binascii import hexlify

filename = argv[1]
with open(filename, 'rb') as f:
    card_data = hexlify(f.read())
    size = 1024
    bbytes = 32
    block = 1
    sector = 0
    print(f'\nSector {sector}')
    for i in range(0, 2*size, bbytes):
        print(f'[{(block-1) % 4}] ' + f'{block-1}' + ' - ' + str(card_data[i:i + bbytes].decode()))
        if block % 4 == 0 and block < 64:
            print(f'Sector {block / 4:g}')
        block += 1