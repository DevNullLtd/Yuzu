| Fault | Addressing | Mgmt addr | Agents | Runs | On victim | Re-registered | Noticed p50 (s) | Re-registered p50 (s) | p99 (s) | Worst (s) | Peak regs/s | Peer FIN/RST (ms) |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| F1 kill | DNS | VIP | 20 | 2 | 9-13 | all | 6.1 | 8.2-8.8 | 10.3-12.7 | 10.3-12.7 | - | 41 |
| F1 kill | DNS | VIP | 100 | 3 | 34-38 | all | 6.9-8.0 | 9.4-9.9 | 12.8-13.2 | 12.8-13.2 | 8-10 | 41-63 |
| F1 kill | DNS | single node | 100 | 1 | 33 | all | 7.4 | 9.0 | 12.6 | 12.6 | 10 | 61 |
| F1 kill | DNS | VIP | 300 | 2 | 110-114 | all | 7.2-7.8 | 9.6-9.9 | 12.7-13.0 | 12.9-13.1 | 23-25 | 45-47 |
| F1 kill | DNS | single node | 300 | 2 | 107-108 | all | 7.4-8.0 | 9.4-9.7 | 13.1 | 13.2 | 28 | 44-95 |
| F1 kill | VIP, default | VIP | 100 | 3 | 34 | all | 7.8-7.9 | 18.4-21.1 | 24.4-26.1 | 24.4-26.1 | 7-10 | 40-72 |
| F1 kill | VIP, redispatch | VIP | 100 | 3 | 34 | all | 6.9-7.1 | 12.8-13.4 | 15.7-16.3 | 15.7-16.3 | 8-9 | 39-68 |
| F1 kill | VIP, default | VIP | 300 | 1 | 100 | all | 7.9 | 18.6 | 24.6 | 24.6 | 22 | 43 |
| F1 kill | VIP, redispatch | VIP | 300 | 1 | 100 | all | 8.0 | 14.0 | 15.9 | 16.2 | 27 | 42 |
| F1g graceful stop | DNS | VIP | 100 | 1 | 44 | all | 7.9 | 10.8 | 16.0 | 16.0 | 15 | 9275 |
| F2p full partition | DNS | VIP | 100 | 1 | 35 | all | 44.7 | 47.5 | 61.7 | 61.7 | 3 | - |
| F2p full partition | VIP, default | VIP | 100 | 3 | 34 | all | 22.6-25.6 | 24.2-27.4 | 28.0-30.4 | 28.0-30.4 | 8-11 | 15441-17717 |
| F2p full partition | VIP, redispatch | VIP | 100 | 2 | 34 | all | 22.8-23.2 | 24.5-26.0 | 28.4-29.1 | 28.4-29.1 | 8 | 15702-16300 |
| F2p full partition | VIP, default | VIP | 300 | 1 | 100 | all | 22.9 | 24.5 | 28.5 | 28.5 | 24 | 15708 |
| F2 agent port only | DNS | VIP | 20 | 1 | 11 | all | 39.0 | 41.5 | 50.5 | 50.5 | - | - |
| F2 agent port only | DNS | VIP | 100 | 3 | 35-44 | all | 43.9-47.5 | 46.2-50.1 | 61.1-62.7 | 61.1-62.7 | 3-4 | - |
| F2 agent port only | DNS | single node | 100 | 1 | 34 | all | 48.2 | 50.7 | 63.3 | 63.3 | 3 | - |
| F2 agent port only (VIP health check stays green) | VIP, default | VIP | 100 | 3 | 34 | **24 of 34** | 114.8-116.5 | 117.6-121.9 | 131.2-135.8 | 131.2-135.8 | 2 | 137812-147455 |
