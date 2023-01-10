## 网络信息获取
> 用来获取系统当前网络状态信息

## 内置方法
- [vela.ss(args, cnd)](#网络信息) &emsp;获取网络信息
- [vela.ss.pid(args , int , cnd)](#进程PID的网络信息) &emsp;获取pid的网络信息
- [vela.ss.process(args , process , cnd)](#进程的网络信息) &emsp;获取process网络信息
- [vela.ss.switch(args, {switch})](#进程switch网络信息) &emsp;进程switch网络信息
- [vela.ss.listen_snapshot(bool)](#进程网络信息) &emsp;开放端口监控
- [vela.ss.inode(v)](#inode) &emsp;查看inode的网络信息


## 网络信息
> [summary](#summary) = vela.ss(args , cnd) <br />
> args:选择参数  cnd:过滤条件 过滤字段[socket](#网络套接字)

args参数说明
```bash
    -4 : IPv4
    -6 : IPv6
    -t : tcp
    -u : udp
    -a : all state 
    -p : process 关联进程
    -l : state listen
    -s : state -s LISTEN -s ETABLISH -s SYN 指定状态
```
```lua
    local s = vela.ss("-a -p -t" , "src = 127.0.0.1")
    print(s.closed)
    print(s.listen)
    print(s.estab)
    print(s.total)

    s.pipe(print)
```

## 进程PID的网络信息
> [summary](#summary) = vela.ss.pid(args ,int, cnd) <br />
> args:选择参数  int:进程pid  cnd:过滤条件 过滤字段[socket](#网络套接字)
```lua
    local s = vela.ss.pid("-a -p -t" ,3, "src = 127.0.0.1")
    print(s.closed)
    print(s.listen)
    print(s.estab)
    print(s.total)

    s.pipe(print)

```
## 进程的网络信息
> [summary](#summary) = vela.ss.process(args ,process, cnd) <br />
> args:选择参数  process:进程对象 cnd:过滤条件 过滤字段[socket](#网络套接字)
```lua
    local p = vela.ps.pid(1)
    local s = vela.ss.process("-a -p -t" ,p, "src = 127.0.0.1")
    print(s.closed)
    print(s.listen)
    print(s.estab)
    print(s.total)

    s.pipe(print)
```

## switch网络信息
> [summary](#summary) = vela.ss.switch(args , {switch}) <br />
> args:选择参数  {switch}:[switch](/switch.md)  过滤字段[socket](#网络套接字)

```lua
    local tab = {
        ['src = 192.168.1.1'] = print,  -- 满足src 等于 192.168.1.1 的问题
        ['src -> risk/ip?have&kind=tor&cache=ss_cache_risk&ttl=30'] = print, -- 命中威胁库
    }

    vela.ss.switch("-p -t" , tab)
```


## 网络汇总
> summary [socket](#网络套接字)信息汇总

内置字段 都是汇总的状态信息:
- closed
- listen
- syn_sent
- syn_rcvd
- estab
- fin_wait_1
- fin_wait_2
- close_wait
- closing
- last_ack
- time_wait
- delete_tcb
- total
- err

内置方法:
- pipe() 遍历[socket](#网络套接字)
- switch(switch) 匹配[socket](#网络套接字)
- find(key , val) 查看查找结果的中的内容,只会匹配一个

```lua
    local s = vela.ss("-l")
    local v = vela.switch()
    v.case("dst = 1.1.1.1").pipe(print)
    s.switch(v)

    
    local socket = s.find("inode" , 10022) --inode
    print(socket)
```

## inode
> 获取inode的socket的内容和信息 <br />
> [socket](#网络套接字) = vela.ss.inode(v) &emsp; 参数为inode的值
```lua
    local s = vela.ss.inode(8763)
    print(s)
```

## 网络套接字
> 网络状态对象结构 结构数据如下

内置字段
- pid
- family
- protocol
- local_addr
- src
- local_port
- src_port
- remote_addr
- dst
- remote_port
- dst_port
- path
- state
- process
- user