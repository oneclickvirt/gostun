# gostun

## Information

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

## Usage

Version: 2024.05.05

```
curl https://raw.githubusercontent.com/oneclickvirt/gostun/main/gostun_install.sh -sSf | sh
```

## Thanks

https://datatracker.ietf.org/doc/html/rfc3489#section-5

https://datatracker.ietf.org/doc/html/rfc4787#section-5

https://github.com/pion/stun/tree/master/cmd/stun-nat-behaviour