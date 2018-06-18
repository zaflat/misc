# IPv4 Stats per interface using Linux kernel ebpf XDP

The sample consists of
* XDP program to be loaded in kernel space XDP vm
* User space Python code to fetch and display the statistics
    * using bcc tools for python
        * to compile and load XDP program into the kernel
        * to fetch statistics
    * playing with curses lib to pretty display the statistics

```
\DP DEMO: RX         17563 IPv4 Packets
---------------------------------------

         ICMP:          10 |*         |
                                         Type
                         2 |**        |  Echo Reply
                         8 |********  |  Echo Request

          TCP:        5870 |***       |
                                         S-Port
                        60 |*         |  22
                        30 |*         |  88
                         7 |*         |  389
                      5693 |********* |  443
                        82 |*         |  5061

          UDP:       11682 |******    |
                                         D-Port
                      1074 |*         |  137
                       183 |*         |  138
                         1 |*         |  1124
                        20 |*         |  1947
                         1 |*         |  3289
                      1161 |*         |  5000
                       353 |*         |  5353
                       356 |*         |  5355
                         2 |*         |  8610
                         2 |*         |  8612
                       455 |*         |  17500
                      7453 |******    |  34329
                       148 |*         |  42538
                       418 |*         |  54915
                        57 |*         |  57621
```
