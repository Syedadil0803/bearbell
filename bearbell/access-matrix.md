# Access matrix

The rulebook bearbell checks the code against: who may do what to whose data. bearbell drafts it from the
code; the owner confirms it. A row marked `guess` is bearbell's reading of the code, not a rule yet.

Confirmed by: <name or role>, <date>. Change a row by editing it and the date.

## Roles
| Role | Who | How they get it |
|---|---|---|
| anyone | not signed in | - |
| user | signed in | sign-up / invite |
| admin | | |

## Objects (data that belongs to someone)
| Object | Owner field | Who else may see it | Hidden fields (by role) |
|---|---|---|---|
| | e.g. `user_id` | | e.g. phone, private notes |

## Actions
`Own only`: yes = only on objects the caller owns. `Owner says`: allow / deny / own only / guess.

| Action | Route | Who (from code) | Object | Own only | Owner says | Confirmed |
|---|---|---|---|---|---|---|

## Business rules
Limits and flows the code must keep (one line each), e.g. "a code works once and for 10 minutes",
"members cannot change their own role or status", "an invite is used once".

-
