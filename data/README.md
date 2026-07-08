# data/ — mandate + execution seed (operator-populated)

MoltProof reads committed mandates from `mandates.json` and (for the pre-live
demonstrator) decoded execution from `actions.json`. Both ship EMPTY: v0 makes no
claims it can't back with real data. The demonstrator (fresh ERC-8004 wallet on
Base + a committed AAE mandate + real trades, incl. one deliberate breach) seeds
the first real entries here. Until then, unknown agents return NO_MANDATE and the
registry is empty — by design.
