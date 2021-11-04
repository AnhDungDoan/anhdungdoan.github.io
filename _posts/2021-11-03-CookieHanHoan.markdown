---
layout: post
title: CookieHanHoan
date: 2021-11-03 00:00:00 +0300
description: WU Crypto # Add post description (optional)
img: CKHH.png # Add image post (optional)
tags: [Crypto, CTF] # add tag
---

# Cúc ki hân hoan

Chào các anh em, giải này củng cố kiến thức kha khá nên làm vui lắm các anh em à <3 

# XOR (146 solves)
> XOR
![image.png](/assets/img/CKHH/xor.png)

encrypt.py
```
flag = ###SECRET###
key = ###SECRET###
assert len(key) == 1

def encrypt(a,b):
    return ''.join([hex(ord(b[i%len(b)]) ^ ord(a[i]))[2:] for i in range(0,len(a))])

with open('cipher.txt', 'w') as f:
	f.write(encrypt(flag, key))
```

cipher.txt
```
6c464b4d514b744817491714487449174b57
```

**Solve:**
- Ở encrypt.py, đơn giản là chỉ encrypt flag của mình và key, sau đó in ra cipher dưới dạng mã hex.
- Đơn giản hóa vấn đề khi mình xem ở file encrypt là độ dài của key = 1. Vậy mình chỉ cần bruteforce key là có thể tìm ra được Flag nào có format "Flag{XXXXXX}" là đúng ời 😎

solve.py
```
import string
def encrypt(a,b):
    return ''.join([chr(ord(b[i%len(b)]) ^ ord(a[i])) for i in range(0,len(a))])

cipher = bytes.fromhex("6c464b4d514b744817491714487449174b57").decode()

for key in string.printable:
    flag = encrypt(cipher, key)
    if ('Flag' in flag):
        print(flag)
```

>FLAG: Flag{a^b=c=>b^c=a}


# MORSE (218 solves)
> Suỵt! Tập trung và đeo tai nghe lên nào. Gà có nghe thấy nhịp beat không? Họ nói gì từ bên kia chiến tuyến Format: Flag{what_you_find}
![image.png](/assets/img/CKHH/morse.png)

**Solve:**
Bài này cho mình 1 file âm thanh <mã morse>. Mình quẳng lên tool là có ngay phờ lác ✌

link tool: https://morsecode.world/international/decoder/audio-decoder-adaptive.html

![image.png](/assets/img/CKHH/morsesolve.png)

>FLAG: Flag{M.O.R.S.E.C.O.D.E}

# Julius Caesar (233 solves)
> Vô tình khi khai quật khảo cổ, Gà tìm được một thông điệp bí ẩn khoảng hơn 100 năm trước công nguyên. Nghe đồn đây là một bí thuật đã bị thay đổi công thức của một vị tướng Julius Caesar, sau này trở thành vị vua đầu tiên của đế chế La Mã hùng mạnh. Hãy giúp Gà giải mật thư này!

![image.png](/assets/img/CKHH/caesar.png)

cipher.txt
```
Synt{Ry_Pynfvpb_Pvcure}
```

**Solve:**
- Những bài có dấu hiệu nhận biết rõ ràng như thế này thì mình nghĩ nên quăng lên tool cho lẹ, tiết kiệm thời gian, độ chính xác tuyệt đối he he 

link tool: https://www.dcode.fr/shift-cipher

![image.png](/assets/img/CKHH/caesarsolve.png)

Flag kìa lụm ngay~~~

>FLAG: Flag{El_Clasico_Cipher}

# Sixty Four (203 solves)
> Gà để lại một thông điệp bí mật nhưng nó không làm khó được trí thông minh của Mèo Yang Hồ.

cipher.txt
```
NDY2QzYxNjc3QjVGNUY1RjQyNjE3MzY1MzYzNDc4NDg2NTc4NUY1RjVGN0Q=
```

**Solve:**
- Nhìn phát biết ngay là mã base64 =))). Thế là mình lại lụm nó quăng vô tool là lá la...

![image.png](/assets/img/CKHH/64solve1.png)

- Ơ, không ra à, nhưng mình được 1 đoạn mã khác, đó là mã hex thì phải, mình quăng vô decode hex luôn cho nó nhanh

![image.png](/assets/img/CKHH/64solve2.png)
- Poong~ lụm tiền

link tool: https://gchq.github.io/CyberChef/
>FLAG: Flag{___Base64xHex___}

# Bruh AES (33 solves)

>Ôi không, Hazy lỡ xoá đi một mảnh ghép trong quá trình mã hoá AES mất rồi :)

![image.png](/assets/img/CKHH/aes.png)

>Đây là một bài gây khó chịu với mình nhất. Không phải vì technique để solve, mà là cách tìm Flag để nộp.

aes.py
```
import base64
from Crypto.Cipher import AES

#flag = ###FINDME###
algorithm = AES.MODE_CBC
key = 'supersecretkey!?'
iv_part1 = "0xcafedeadbeef"
iv_part2 = ###FINDME###"" 
iv = iv_part1 + iv_part2
#assert(len(flag)) == 38

def encrypt(payload, key, iv):
    return AES.new(key, algorithm, iv).encrypt(r_pad(payload))

def r_pad(payload, block_size=16):
    length = block_size - (len(payload) % block_size)
    return payload + chr(length) * length

with open('cipher.txt', 'wb') as f:
    f.write(encrypt(flag, key, iv)) 
```

**Problem:**
- Mình đi qua lý thuyết về AES mode CBC 1 chút:

![image.png](/assets/img/CKHH/aescbc.png)

- Thì các anh em có thể thấy, block đầu tiên của plaintext sẽ xor qua IV, sau đó vào 1 đống việc tính toán phức tạp của AES, cho ra 1 block cipher, sau đó dùng để xor với block thứ 2 của plaintext and go on.....
- Nhưng ở file aes.py mình down về, có thế thấy iv_part1 có độ dài là 14. Trong khi 1 block có độ dài là 16, thì việc mình cần làm là tìm 2 kí tự cuối của IV. Gud xờ kiu lại là brute-force 😜

solve.py
```
iv_part1 = "0xcafedeadbeef"

import sys
import base64
import string 
from Crypto.Cipher import AES

key = b'supersecretkey!?'
sys.stdin = open("cipher.txt", "rb")
sys.stdout = open("flag.txt", "w")
algorithm = AES.MODE_CBC

def decrypt(payload, key, iv):
    cip = AES.new(key, algorithm, iv)
    return cip.decrypt(payload)

cipher = input()

for i in string.printable:
    for j in string.printable:
        iv = iv_part1 + i + j
        enc = decrypt(cipher, key, iv.encode())
        ans = enc[:38].decode()
        if (ans[15] in string.hexdigits and ans[14] in string.hexdigits):
            print("iv :", iv, "flag:", ans)    
```

*chỗ ans=enc[:38] là mình chôm 38 kí tự đầu thôi do flag mỗi 38 kí tự*

- Mình in ra file tên là *flag.txt*. Nhìn xemmmmmmmmmmmmmmm

![image.png](/assets/img/CKHH/aesflag.png)

- Ơ? Thế cái nào mới là flag đúng? Mình đi hỏi admin về flag cụ thể nhưng không ăn thua... Phải tự mò vậy

- Hmm nói chung là 2 ksi tự cuối của iv là 'x0', đồng nghĩa là mình tìm được Flag. Còn lý do vì sao là 'x0' á? Vì nó đối xứng với 2 kí tự đầu của IV 🤔. *superguesser*

>FLAG: Flag{f4edced3a1c3e72be1257f232a7a78b6}

# Cry more (19 solves)
>Mã mua dài quá nên không mua được :(
>Bạn có thể mua flag hộ Hazy được không :D
> nc chal1.crypto.letspentest.org 7000

![image.png](/assets/img/CKHH/crymore.png)

server.py
```
import datetime
import os
import random
import socketserver
import sys
from base64 import b64decode, b64encode
from hashlib import sha512


def get_flag():
    try:
        with open('flag.txt', 'rb') as f:
            flag = f.read()
            return flag
    except Exception as e:
        print(e)
        return b'Server is not configured correctly. Please contact admins to fix the problem'


items = [
    (b'Fowl x 3', 1),
    (b'Mora x 30000', 100),
    (b'Mystic Enhancement Ore x 5', 500),
    (b'Hero\'s Wits x 3', 1000),
    (b'Primogems x 40', 5000),
    (b'FLAG', 99999)
]


class RequestHandler(socketserver.StreamRequestHandler):

    def handle(self):
        self.signkey = os.urandom(random.randint(8, 32))
        self.money = random.randint(1, 2000)
        try:
            while True:
                self.menu()

                try:
                    self.request.sendall(b'Your choice: ')
                    opt = int(self.rfile.readline().decode())
                except ValueError:
                    self.request.sendall(
                        b'THIS IS A CRYPTOGRAPHIC CHALLENGE!!!\n')
                    continue
                if opt == 1:
                    self.list()
                elif opt == 2:
                    self.order()
                elif opt == 3:
                    self.confirm()
                elif opt == 4:
                    self.request.sendall(b'Bye~\n')
                    return
                else:
                    self.request.sendall(b'Ohh~\n')

        except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError):
            print("{} disconnected".format(self.client_address[0]))

    def menu(self):
        self.request.sendall(
            b'To celebrate `our` first anniversary, we are offering you tons of product at the best prices\n')
        self.request.sendall(b'You have $%d\n' % self.money)
        self.request.sendall(b'1. Available products\n')
        self.request.sendall(b'2. Order\n')
        self.request.sendall(b'3. Confirm order\n')
        self.request.sendall(b'4. Exit\n')

    def list(self):
        for idx, item in enumerate(items):
            self.request.sendall(b'%d - %s: $%d\n' %
                                 (idx + 1, item[0], item[1]))

    def order(self):
        try:
            self.request.sendall(b'ID: ')
            pid = int(self.rfile.readline().decode())
        except ValueError:
            self.request.sendall(
                b'THIS IS A CRYPTOGRAPHIC CHALLENGE!!!\n')
            return

        if pid < 1 or pid > len(items):
            self.request.sendall(b'Ohh~\n')
            return

        payment = b'product=%s&price=%d&time=%.02f' % (
            items[pid-1][0], items[pid-1][1], datetime.datetime.now().timestamp())
        signature = sha512(self.signkey+payment).hexdigest()
        payment += b'&sign=%s' % signature.encode()
        self.request.sendall(b'Your order: ')
        self.request.sendall(b64encode(payment))
        self.request.sendall(b'\n')

    def confirm(self):
        try:
            self.request.sendall(b'Your order: ')
            payment = b64decode(self.rfile.readline().rstrip(b'\n'))
        except Exception:
            self.request.sendall(
                b'THIS IS A CRYPTOGRAPHIC CHALLENGE!!!\n')
            return

        pos = payment.rfind(b'&sign=')
        if pos == -1:
            self.request.sendall(b'Invalid order\n')
            return

        signature = payment[pos + 6:]
        if sha512(self.signkey+payment[:pos]).hexdigest().encode() != signature:
            self.request.sendall(b'Invalid order\n')
            return

        m = self.parse_qsl(payment[:pos])
        try:
            pname = m[b'product']
            price = int(m[b'price'])
        except (KeyError, ValueError, IndexError):
            self.request.sendall(b'Invalid order\n')
            return

        if price > self.money:
            self.request.sendall(b'Oops\n')
            return

        self.money -= price
        self.request.sendall(
            b'Transaction is completed. Your balance: $%d\n' % self.money)
        if pname == b'FLAG':
            print("{} solved the challenge".format(self.client_address[0]))
            self.request.sendall(b'Here is your flag: %s\n' % get_flag())
        else:
            self.request.sendall(
                b'%s will be delivered to your in-game mailbox soon\n' % pname)

    def parse_qsl(self, query):
        m = {}
        parts = query.split(b'&')
        for part in parts:
            key, val = part.split(b'=')
            m[key] = val
        return m


class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    pass


def main(argv):
    host, port = 'localhost', 8000

    if len(argv) == 2:
        port = int(argv[1])
    elif len(argv) >= 3:
        host, port = argv[1], int(argv[2])

    sys.stderr.write('Listening {}:{}\n'.format(host, port))
    server = ThreadedTCPServer((host, port), RequestHandler)
    server.daemon_threads = True
    server.allow_reuse_address = True
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    server.server_close()


if __name__ == '__main__':
    main(sys.argv)
```

*đùa không zui tui đã kăng*

ok ngó nào

**Problems:**
- Chúng ta vô shop mua đồ, với số tiền random trong khoảng từ 1 đến 1999. Trong khi FLAG giá tận 9999 lận? Phải tìm cách mua thôi
- Ồ, đây là thứ ta cần chú ý trong hàm *order*:
```
payment = b'product=%s&price=%d&time=%.02f' % (
            items[pid-1][0], items[pid-1][1], datetime.datetime.now().timestamp())
        signature = sha512(self.signkey+payment).hexdigest()
        payment += b'&sign=%s' % signature.encode()
```
- Ồ đây là 1 bài về hash. Cụ thể là SHA-512. Mình nghĩ ngay đến cách tấn công gọi là *hash length extension attack*. Các bạn có thể đọc hiểu cách hoạt động cụ thể ở [link này này bấm bấm](https://github.com/iagox86/hash_extender).
- Về đoạn signkey được chèn vào sẽ có độ dài random từ 8 đến 32, mình không cần quan tâm đến giá trị đó làm gì vì khi attack, mình sẽ đẩy hết đoạn signkey đó đi. Do không biết cụ thể nên mình lại brute-force vậy 🙄
- Tiếp tục mình nhó qua hàm *parse_qsl*. Chỗ này mục đích tách các thành phần ra thôi, mình sẽ lợi dụng chỗ này để attack vào, cụ thể là thêm chuỗi "product=FLAG" sau khi chọn mua món hàng đầu tiên! Mà món hàng đầu tiên luôn là giá 1đ, nên mình luôn có thể mua được 😁. Thì sau khi mình truyền chuỗi sau khi thêm "product=FLAG", hàm *parse_qsl* sẽ thực thi và món hàng mình mua sẽ là FLAG, chứ không phải là món hàng đầu tiên nữa.


solve.py
```
from pwn import *
from base64 import b64encode, b64decode
from hashpumpy import hashpump

def parse_qsl(query):
    m = {}
    parts = query.split(b'&')
    for part in parts:
        key, val = part.split(b'=')
        m[key] = val
    return m

while True:
    io = remote('chal1.crypto.letspentest.org', 7000)

    io.recv()
    io.sendline(b'2')
    io.sendline(b'1')
    io.recvuntil(b'Your order: ')
    payment = io.recvline()
    io.recv()

    payment = b64decode(payment)
    signature = parse_qsl(payment)
    signature = signature[b'sign']

    payment = payment.split(b'&')
    del payment[3]
    payment = b'&'.join(payment)

    for i in range(8,33):
        new_signature, new_data = hashpump(signature, payment, '&product=FLAG', i)
        
        payload = new_data + b'&sign=' + new_signature.encode()
        payload = b64encode(payload)
        
        io.sendline(b'3')
        io.recv()
        io.sendline(payload)
        result = io.recvline()
        if b'Invalid order' in result:
            io.recv()
            continue
        else:
            #print(result)
            print(io.recvline())
            exit(0)
```

> **note:** mấy anh em nào mà chạy code này thì phải qua ubuntu hoặc linux chạy nha, vì mình dùng thư viện hashpump ấy

Sau 1 hồi chạy.... flag sẽ được trả ra:

>FLAG: Flag{hashlengthextensionattack}

Cám ơn các anh em đã đọc hết nha he he he he.

