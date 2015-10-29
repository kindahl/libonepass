# Introduction
libonepass is a C++11 library for importing (reading)
[1Password](https://agilebits.com/onepassword) 4 cloud password databases.
Currently there is only support for importing, imported content cannot be
modified and exported into a 1Password database.

This library was created for the purpose of understanding the 1Password database
format and for importing databases into a different format. It's been released
here in the hope that someone will find it useful.

# Building
The following 3rd party libraries are required to build libonepass:
* [OpenSSL](https://www.openssl.org/)

For running the unit tests [googletest](https://code.google.com/p/googletest/)
is also required.

To build, simply do the following:
```sh
make -j8
```

to run the unit tests, do the following:
```sh
make test
```

# Using
First load and unlock a profile. Then load the database using the path to the
vault and the loaded profile.

Example:
```cpp
Profile profile;
profile.Load("<path to vault>/default/profile.js");
profile.Unlock("<password>");

Database db;
db.Load("<path to vault>", profile);

// Fetch the login items using: db.GetLoginItems().
```
