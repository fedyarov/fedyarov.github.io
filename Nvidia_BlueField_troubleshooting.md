# Nvidia Bluefield troubleshooting

## Host troubles
### There is no DPU interafaces on Host
**Symptoms**
- `devlink port show prints nothing

**How to repair**
```
sudo /etc/init.d/openibd restart
```

## Connect to DPU from host troubles
### There is no `tmfifo_net0` interface on Host
1. `tmfifo_net0` will setup with `rshim` service
```
systemctl restart rshim
```

## DPU troubles
### No network intefaces on DPU
**Symptoms**
- `devlink port show` prints nothing

**How to repair**
```
sudo mlxconfig -d 03:00.1 s LINK_TYPE_P1=ETH LINK_TYPE_P2=ETH
```
