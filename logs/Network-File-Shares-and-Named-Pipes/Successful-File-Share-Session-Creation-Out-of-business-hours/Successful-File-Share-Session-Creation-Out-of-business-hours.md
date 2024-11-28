event.code: 5140 AND (hour_of_day: [* TO 7] OR hour_of_day: [17 TO *]) AND winlog.event_data.ObjectTyppe: "File" AND winlog.keywords:"Audit Success"
