event.code: 4741 AND winlog.keywords: "Audit Success" AND NOT winlog.event_data.PasswordLastSet: "%%1794" AND (hour_of_day: [* TO 7] OR hour_of_day: [17 TO *])
