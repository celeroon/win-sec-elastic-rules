event.code: 4674 AND winlog.keywords: "Audit Success" AND winlog.event_data.ObjectServer: "Win32 SystemShutdown module" OR event.code: 1074 AND winlog.event_data.param5: ("power off" OR "shutdown") AND host.name: ("DC01" OR "CRITICAL_HOST01")