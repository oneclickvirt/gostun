# gostun

[![Hits](https://hits.spiritlhl.net/gostun.svg?action=hit&title=Hits&title_bg=%23555555&count_bg=%230eecf8&edge_flat=false)](https://hits.spiritlhl.net)

[![Build and Release](https://github.com/oneclickvirt/gostun/actions/workflows/main.yaml/badge.svg)](https://github.com/oneclickvirt/gostun/actions/workflows/main.yaml)

本机NAT类型检测工具

Local NAT type detection tool (NatTypeTester)

## 类型说明[Information]

```
NatMappingBehavior:
inconclusive
endpoint independent (no NAT)
endpoint independent
address dependent
address and port dependent
```

```
NatFilteringBehavior:
inconclusive
endpoint independent
address dependent
address and port dependent
```

| NAT Type             | Nat Mapping Behavior          | Nat Filtering Behavior         |
|----------------------|------------------------|----------------------|
| Full Cone        | ```endpoint independent``` | ```endpoint independent``` |
| Restricted Cone  | ```endpoint independent```   |  ```address dependent```  |
| Port Restricted Cone |  ```endpoint independent```   |  ```address and port dependent```  |
| Symmetric       | ```address and port dependent``` | ```address and port dependent``` |
| Inconclusive    |           ```inconclusive```    |  ```inconclusive```         |

## 使用说明[Usage]

下载、安装、更新

```
curl https://raw.githubusercontent.com/oneclickvirt/gostun/main/gostun_install.sh -sSf | sh
```

使用

```
gostun
```

或

```
./gostun
```

进行测试

无环境依赖，理论上适配所有系统和主流架构，更多架构请查看 https://github.com/oneclickvirt/gostun/releases/tag/output

```
Usage: gostun [options]
  -e    Enable logging functionality (default true)
  -h    Display help information
  -server string
        Specify STUN server address (default "stun.voipgate.com:3478")
  -timeout int
        Set timeout in seconds for STUN server response (default 3)
  -type string
        Specify ip test version: ipv4, ipv6 or both (default "ipv4")
  -v    Display version information
  -verbose int
        Set verbosity level
```

![图片](https://github.com/oneclickvirt/gostun/assets/103393591/303afc84-b92f-4e16-9d6c-1c9aa34a1221)


## 卸载

```
rm -rf /root/gostun
rm -rf /usr/bin/gostun
```

## 在Golang中使用

```
go get github.com/oneclickvirt/gostun@v0.0.4-20250722054248
```

## 感谢[Thanks]

https://www.rfc-editor.org/info/rfc5389

https://datatracker.ietf.org/doc/html/rfc3489#section-5

https://datatracker.ietf.org/doc/html/rfc4787#section-5

https://github.com/pion/stun/tree/master/cmd/stun-nat-behaviour
