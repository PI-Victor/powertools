Leaf
---

A network administrator's swiss knife.  
Leaf can display ongoing tcp/udp traffic on a specific interface.  
It can also list all interfaces of the underlying system.

```shell
$ leaf interfaces --list
lo0: flags=8049<UP,LOOPBACK,MULTICAST,RUNNING>
      index: 1
      ether: 00:00:00:00:00:00
       inet: 127.0.0.1/8
      inet6: ::1/128
      inet6: fe80::1/64
...
```

```shell
$ sudo leaf sniff --interface en0
Udp - 192.168.1.100 -> 224.0.0.251: size: 538
Tcp - 192.168.1.100 -> 192.168.1.101: size: 113
Tcp - 192.168.1.100 -> 192.168.1.102: size: 23
...
```