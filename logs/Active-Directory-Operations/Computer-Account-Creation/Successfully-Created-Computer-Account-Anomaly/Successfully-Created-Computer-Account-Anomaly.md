event.code: 4741 AND winlog.keywords: "Audit Success" AND NOT winlog.event_data.DisplayName: "-" OR NOT winlog.event_data.UserPrincipalName: "-" OR NOT winlog.event_data.HomeDirectory: "-" OR NOT winlog.event_data.HomePath: "-" OR NOT winlog.event_data.ScriptPath: "-" OR NOT winlog.event_data.ProfilePath: "-" OR NOT winlog.event_data.UserWorkstations: "-" OR NOT winlog.event_data.AllowedToDelegateTo: "-"