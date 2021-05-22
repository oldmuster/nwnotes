### 案例1-MSF&CobaltStrike联动Shell
#### CS->MSF
```
创建Foreign监听器->MSF监听模块设置对应地址端口->CS执行Spawn选择监听器
```
#### MSF->CS
```
CS创建监听器->MSF载入新模块注入设置对应地址端口->执行CS等待上线
use exploit/windows/local/payload_inject
```