# gostun

[![Hits](https://hits.seeyoufarm.com/api/count/incr/badge.svg?url=https%3A%2F%2Fgithub.com%2Foneclickvirt%2Fgostun&count_bg=%2342FFEA&title_bg=%23555555&icon=sonarcloud.svg&icon_color=%23E7E7E7&title=hits&edge_flat=false)](https://hits.seeyoufarm.com) [![Build and Release](https://github.com/oneclickvirt/gostun/actions/workflows/main.yaml/badge.svg)](https://github.com/oneclickvirt/gostun/actions/workflows/main.yaml)

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

## TODO

- [ ] 加入UDP检测

## 使用说明[Usage]

更新时间[Version]: 2024.05.05

```
curl https://raw.githubusercontent.com/oneclickvirt/gostun/main/gostun_install.sh -sSf | sh
```

更多架构请查看 https://github.com/oneclickvirt/gostun/releases/tag/output

```
  -server string
        STUN server address (default "stun.voipgate.com:3478")
  -timeout int
        the number of seconds to wait for STUN server's response (default 3)
  -verbose int
        the verbosity level
```

![图片](https://github.com/oneclickvirt/gostun/assets/103393591/303afc84-b92f-4e16-9d6c-1c9aa34a1221)

## 感谢[Thanks]

https://datatracker.ietf.org/doc/html/rfc3489#section-5

https://datatracker.ietf.org/doc/html/rfc4787#section-5

https://github.com/pion/stun/tree/master/cmd/stun-nat-behaviour
