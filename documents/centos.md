### vnc Server



- sudo yum install tigervnc-server

- sudo cp  /lib/systemd/system/vncserver@.service   /etc/systemd/system/vncserver@.service
- sudo vim  /etc/systemd/system/vncserver@.service
- sudo systemctl daemon-reload
- sudo systemctl enable vncserver@:1.service
- sudo vncpasswd ~/.vnc/paawd
- sudo firewall-cmd  --state
- sudo firewall-cmd  --zone=public --add-port=5901/tcp  --permanent
- sudo firewall-cmd  --zone=public --add-port=6001/tcp  --permanent
- sudo firewall-cmd --reload
- sudo firewall-cmd --list-all
- 



### Centos 关闭selinux 和防火墙

- vim /etc/selinux/config

- 查看防火墙状态

  ```
  firewall-cmd --state1
  ```

  停止firewall

  ```
  systemctl stop firewalld.service1
  ```

  禁止firewall开机启动

  ```
  systemctl disable firewalld.service 
  ```


