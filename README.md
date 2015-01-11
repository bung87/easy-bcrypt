Brief Example
-------------

Hashing a password:

    let passwordHash = hashPw(password, genSalt(12))

Verifying a password:

    let savedHash = ...
    assert hashPw(password, savedHash) == savedHash

Storing a password in a database:

    let passwordString = $passwordHash
    dbconn.exec("...", passwordString)
