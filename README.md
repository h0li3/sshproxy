## sshproxy

SOCKS5 tunnel through the TCP forwarding channel of SSH.

### 描述

`sshproxy`用libssh2连接SSH服务器并在服务器绑定一个端口用于反向SOCKS5代理，此功能等同于openssh中的ssh -R [port]。
由于libssh2在windows平台只支持select模式，故而`sshproxy`也使用select，如果并发量较大会处理不过来，有需要可以改动libssh2的代码移植到IOCP。

