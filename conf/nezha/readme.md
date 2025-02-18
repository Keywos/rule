## nezha: 

* [哪吒监控原仓库](https://github.com/naiba/nezha)
* [我修改的主题，自定义代码style放到对应地方](https://github.com/Keywos/rule/raw/main/conf/key.css)
* 按月流量统计，避免vps重启后过去的监控流量数据丢失
### 预览图
![](https://github.com/Keywos/rule/raw/main/tv/nzpc.png)
![](https://github.com/Keywos/rule/raw/main/tv/nzpc2.png)

### iOS预览图
![](https://github.com/Keywos/rule/raw/main/tv/nz.jpg)

* 以下为解释：详细说明请看原作者文档
```
[{"type":"transfer_all_cycle", 上下行都会统计，transfer_in_cycle 周期内的入站流量，transfer_out_cycle 周期内的出站流量，transfer_all_cycle 周期内双向流量和
"max":1099511627776, 总流量字节为单位 此数值为1t
"cycle_start":"2023-02-05T21:00:00+08:00", 开始计算日期
"cycle_interval":1, 每隔多少个周期单位
"cycle_unit":"month", 统计周期单位，默认hour,可选(hour, day, week, month, year)
"cover":1, 0 监控所有，通过 ignore 忽略特定服务器，1 忽略所有，通过 ignore 监控特定服务器
"ignore":{"1":true}}] 监控对应机器id
```

* 按月流量统计复制以下代码
* 进入后台管理员->报警->添加报警规则
```
[{"type":"transfer_all_cycle","max":1099511627776,"cycle_start":"2023-02-05T21:00:00+08:00","cycle_interval":1,"cycle_unit":"month","cover":1,"ignore":{"1":true}}]
```
![](https://github.com/Keywos/rule/raw/main/tv/nzjc.png)
![](https://github.com/Keywos/rule/raw/main/tv/nzjc2.png)
