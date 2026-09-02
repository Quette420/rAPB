mysql -u root

use apb_2013;

truncate characters;

INSERT INTO accounts
(
Username,
Password,
Verifier,
Salt,
Threat,
IsAdmin,
IsBanned,
InUse,
CanHostDistrict,
Token
)
VALUES
(
'test',
'test',
'',
'',
0,
1,
0,
0,
1,
''
);