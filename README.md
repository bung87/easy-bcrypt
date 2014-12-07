Brief Example
-------------

Hashing a password:

    let passwordHash = hashPw(password, genSalt(12))

Verifying a password:

    let savedHash = ...
    assert hashPw(password, savedHash) == savedHash

IMPORTANT NOTE: using strcmp or memcmp like in this simple example may make
your code vulnerable to timing attacks[1]. If possible, use a function that
always compares all the characters in the string before returning.

[1] https://en.wikipedia.org/wiki/Timing_attack
