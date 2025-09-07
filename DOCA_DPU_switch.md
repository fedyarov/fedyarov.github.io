# From zero to simple DOCA switch on NVIDIA BlueField DPU

## 1. Install DOCA framework on your host machine

## 2. Install DOCA fireware on your DPU from host
## 3. Optionally install DOCA SDK on your development machine
## 4. Build reference application `doca_secure_channel`. 
Congrats, you have done your configurations and now you can develop DOCA applications! You might think, but no. Try to buid `doca_switch` and you get bunch of errors that doesn't googled.
## 5. Find out what we need to run **reference application**. 
Создание VFs по гайду от Nvidia
Гайд говорит нам выполнить
```
$ mlxreg -d /dev/mst/mt41686_pciconf0 --reg_id 0xc007 --reg_len 0x40 --indexes "0x0.0:32=0x80000000" --yes --set "0x4.0:32=0x1"
```
Но возвращается ошибка. Наверное так и должно быть, пропустим этот шаг

We built `doca_switch`, deploy it on DPU, find out our VFs (what VFs ?), run application and get bunch of errors with Segmentation fault in the end. Как-будто нам и без этого было мало дел:
```
ubuntu@localhost:~/Projects/doca_switch$ sudo ./doca_switch -- -r pci/03:00.1,pf1vf[0-1] -l 70
[16:17:42:188973][2468749344][DOCA][INF][doca_log.cpp:628] DOCA version 3.1.0105
EAL: Detected CPU lcores: 8
EAL: Detected NUMA nodes: 1
EAL: Detected shared linkage of DPDK
EAL: Multi-process socket /var/run/dpdk/rte/mp_socket
EAL: Selected IOVA mode 'PA'
TELEMETRY: No legacy callbacks, legacy socket not created
EAL: Probe PCI driver: mlx5_pci (15b3:a2d6) device: 0000:03:00.1 (socket -1)
mlx5_net: Unified FDB is not supported with this FW version.
EAL: Probe PCI driver: mlx5_pci (15b3:a2d6) device: 0000:03:00.1 (socket -1)
mlx5_net: Unified FDB is not supported with this FW version.
[16:17:42:356870][2468749344][DOCA][INF][flow_switch_common.c:137][get_dpdk_nb_ports] Port ID 0 is valid DPDK port
[16:17:42:356922][2468749344][DOCA][INF][flow_switch_common.c:137][get_dpdk_nb_ports] Port ID 1 is valid DPDK port
[16:17:42:356935][2468749344][DOCA][INF][flow_switch_common.c:137][get_dpdk_nb_ports] Port ID 2 is valid DPDK port
mlx5_net: port 0 cannot enable promiscuous mode in flow isolation mode
[16:17:42:656358][2468749344][DOCA][DBG][dpdk_utils.c:181][port_init] Port 0 MAC: b8 ce f6 4d c9 41
[16:17:42:656414][2468749344][DOCA][INF][dpdk_utils.c:126][port_init] Skip represent port 1 init in switch mode
[16:17:42:656428][2468749344][DOCA][INF][dpdk_utils.c:126][port_init] Skip represent port 2 init in switch mode
[16:17:42:656516][2468749344][DOCA][WRN][engine_model.c:88] adapting queue depth to 128.
NV_HWS[cmd_stc_create:514]: Failed to create STC (syndrome: 0x6fa08b)
NV_HWS[pool_create_one_resource:63]: Failed to allocate resource objects
NV_HWS[pool_resource_alloc:87]: Failed allocating resource
NV_HWS[pool_create_resource_on_index:271]: Failed to create resource type: 1: size 15 index: 0
NV_HWS[pool_element_create_new_elem:309]: Failed to create resource type: 1: size 15 index: 0
NV_HWS[pool_onesize_element_get_mem_chunk:362]: Failed to allocate element for order: 0
NV_HWS[pool_onesize_element_db_get_chunk:452]: Failed to get free slot for chunk with order: 0
NV_HWS[action_alloc_single_stc:384]: Failed to allocate single action STC
NV_HWS[action_dest_create_stc:463]: Failed to allocate STC table type [6]
[16:17:42:811861][2468749344][DOCA][ERR][nv_hws_wrappers.c:418] failed to create dest action ROOT, flag 64, err -121
[16:17:42:828179][2468749344][DOCA][ERR][dpdk_port_legacy.c:275] failed to create port - creating dpdk port
Segmentation fault
```

First, find out что кому принадлежит. Логи `EAL:` принадлежал DPDK, `mlx5_net` модулю ядра `mlx5_core`, `NV_HWS` - ?????. Неизвестно, что такое NV_HWS. Гугл выдает всего один результат на страницу Nvidia Docs с похожим описанием, но она удалена. Такая же история с STC. Уточняем у искусственного коллеги, но пока не верим.

**Что такое STC**
```

STC = Steering Table Context (или Single Table Context, точное название в FW не публичное).

Это структура в аппаратной части (ASIC/DPAA, Mellanox HWS), в которой хранятся правила перенаправления пакетов: flow, action, match.

Когда DOCA Flow создаёт «порт» или «flow», драйвер пытается выделить STC для таблиц действий, которые будут оффлоадиться на железо.
```
