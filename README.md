# gostun

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
| Full Cone        | ```endpoint independent (no NAT)``` | ```endpoint independent``` |
| Restricted Cone  |    |    |
| Port Restricted Cone |     |    |
| Symmetric       | ```address dependent```、```address and port dependent``` |  |

## Thanks

https://datatracker.ietf.org/doc/html/rfc3489#section-5

https://datatracker.ietf.org/doc/html/rfc4787#section-5

https://github.com/pion/stun/tree/master/cmd/stun-nat-behaviour