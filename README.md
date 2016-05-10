# Infestor - A Petya Solver
Petya is a relatively new crypt-ransomware that has been spreading in recent months (March - April 2016). When the user executes the PETYA .exe, the Petya then proceeds to overwrite the master boot record and encrypt the entire hard drive, holding the user's data as hostage until a ransom is paid. However it was discovered that Petya uses a [Salsa20][Salsa] (the 16 bit variation of the [salsa stream cipher][salsaStream]) to encrypt the hard drive, and ultimately Infestor is a python project dedicated to performing cryptoanalysis on Petya.  

Report
-------
The complete write-up can be found at https://github.com/peixian/Infestor/blob/master/paper/paper.pdf. 

Noticible Differences Between Actual Salsa20 and BadSalsa
--------------
1. Uses `uint16_t` instead of `uint32_t` - results in static bit shifts
2. `s20_rev_littleendian` (line `49` in `samples/badsalsa.c`)
3. BadSalsa lacks the `s20_expand16` function, so the `s20_crypt` function always expands by `s20_expand32`

Notes
------
- A **live** petya sample can be found in the `petyaSample` folder, exercise caution with this, courtesy of https://github.com/ytisf/theZoo.  
- VMDKTemplate is meant to be used with 010Editor, slightly changed to only display the first grain.

References
----------
- Salsa20 Wikipedia: https://en.wikipedia.org/wiki/Salsa20
- Salsa20 Spec: https://cr.yp.to/snuffle/spec.pdf
- z3 Documentation: https://z3prover.github.io/api/html/z3.html
- Genetic Go Solver: https://github.com/leo-stone/hack-petya
- Online Solver: https://petya-pay-no-ransom-mirror1.herokuapp.com/
- Salsa20 Actual Implementation: https://github.com/alexwebr/salsa20/blob/master/salsa20.c
- 010 Editor Template: https://github.com/extremecoders-re/VMDK-Template
- Sample Source: https://github.com/ytisf/theZoo
- Decryption of Petya: http://blog.checkpoint.com/2016/04/11/decrypting-the-petya-ransomware/
- Petya X-Ray: http://www.tgsoft.it/english/news_archivio_eng.asp?id=718

[Salsa]: https://cr.yp.to/salsa20.html
[salsaStream]: https://cr.yp.to/snuffle.html