event.code: 4741 AND winlog.keywords: "Audit Success" AND winlog.event_data.SamAccountName: ("-" OR "") OR NOT _exists_:winlog.event_data.SamAccountName
