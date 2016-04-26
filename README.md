# Infestor - A Petya Solver
Petya is a relatively new crypt-ransomware that has been spreading in recent months (March - April 2016). When the user executes the PETYA .exe, the Petya then proceeds to overwrite the master boot record and encrypt the entire hard drive, holding the user's data as hostage until a ransom is paid. However it was discovered that Petya uses a [Salsa20][Salsa] (the 16 bit variation of the [salsa stream cipher][salsaStream]) to encrypt the hard drive, and ultimately Infestor is a python project dedicated to performing cryptoanalysis on Petya.  

- Salsa20 Spec: https://cr.yp.to/snuffle/spec.pdf


[Salsa]: https://cr.yp.to/salsa20.html
[salsaStream]: https://cr.yp.to/snuffle.html