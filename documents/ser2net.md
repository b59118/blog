### ser2net 命令

- 参考文档  https://www.twblogs.net/a/5c0cf2e4bd9eee5e40ba9510

  1. 修改配置文件

     ``` 
     vim   /etc/ser2net.conf
     # telnet 
     #  <TCP port>:<state>:<timeout>:<device>:<options>
     20053:telnet:14400:/dev/ttyUSB5:115200 8DATABITS NONE 1STOPBIT LOCAL banner
     ```

  2. 重启 ser2net 服务

     sudo service ser2net restart
