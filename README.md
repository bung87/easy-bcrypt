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

Loading a password from a database:

    let password = dbconn.exec(
      "SELECT password FROM users WHERE username = ?;", username)
    let passwordSalt = loadPasswordSalt(password)
