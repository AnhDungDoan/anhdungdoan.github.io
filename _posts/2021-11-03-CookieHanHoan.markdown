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