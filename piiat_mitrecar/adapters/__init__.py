"""Format adapters — the "artefact ≠ processor" principle, made structural.

The CAR maps are keyed to the ARTEFACT (the Windows event log, the NTFS
filesystem, a network flow), never to the tool that parsed it. When two
processors parse the same artefact in different output formats, ONE of them is
the canonical map shape and the other gets a format adapter here:

- `winevt`: a Plaso windows:evtx:record / windows:evt:record → the EvtxECmd
  record shape, so the identical evtx maps serve both processors (verified
  byte-identical CAR output on the same evidence).
- `l2t_split`: a raw log2timeline json_line file is a CONTAINER of many
  parsers — streamed and split into per-parser table files the maps consume.

A new processor for an already-mapped artefact should land here as an adapter,
never as a second map set.
"""
