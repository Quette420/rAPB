mysql -u root

use apb_2013;

truncate characters;

INSERT INTO `accounts`
(
`Index`,
`Username`,
`Password`,
`Verifier`,
`Salt`,
`Threat`,
`IsAdmin`,
`IsBanned`,
`InUse`,
`CanHostDistrict`,
`Token`
)
VALUES
(
1,
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