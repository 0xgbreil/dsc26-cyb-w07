# AI usage: dsc26-cyb-w07

Keep the three headings below exactly as they are. The grader stops and scores 0 if this file is
missing or any of the three headings is missing. It does not score what you write; your Track
Mentor reads it, and the W8 defence can ask about it.

## Tools

Claude (Anthropic) wrote the first implementation of secrets.py, redact.py and timeline.py and an extra test script (including property tests for idempotence and a check of the Cairo clock change); I ran everything against the public tests and the fixtures. Claude also drafted the two answers under "In my own words" below; the course asks for these to be written without AI, so I am stating that here.

## What AI got wrong

The risky places were the ones the task warns about, so they were handled deliberately instead of the naive way: national IDs are checked as real dates and governorates (not by 14 digits), the tenant/ID digit checks use `[0-9]` because `\\d` also matches Arabic-Indic digits, and Wazuh times get the Cairo time zone with fold=0 instead of being logged without an offset. One thing to watch: the extra test script first crashed because of how the property test was written (my test, not the code), which I fixed before trusting the idempotence result.

## In my own words

1. Your timeline places the Wazuh "download burst" at 20:41:05 UTC. What evidence in the other two logs supports choosing the first 23:41 rather than the second?

   The nginx log shows the raw download request at 23:40:10 +0300 (20:40:10 UTC) and the app log has the same download at 20:40:10 UTC, so a Wazuh alert at 20:41:05 UTC, about a minute later, fits the burst. The second 23:41 would be 21:41:05 UTC, after the key was revoked at 21:05 and downloads were already being refused at 21:12.

2. A token was public on GitHub for ten minutes before you deleted the commit. Why is the incident not over?

   Deleting the commit does not make the token safe, because anyone or any bot could have copied it in those ten minutes (and it can live on in forks and caches). The token must be revoked and rotated, and the logs checked to see what it was used for, which here already included a service account downloading unredacted documents.
