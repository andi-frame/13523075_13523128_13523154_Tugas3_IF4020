Fixture publik **khusus pengujian**. Jangan memakai pasangan TEST_ONLY untuk
rilis nyata atau memasukkan fingerprint-nya ke trust store produksi.

`demo.bin`: byte tetap, mencakup NUL, byte non-UTF-8, dan CRLF.
`manifest.json`: canonical literal tanpa newline akhir, paket `demo`, versi `1.0`.
`bundle.json`: signature RSA-PSS sah atas byte manifest tersebut.
`trust.json`: contoh store dengan public key yang mengizinkan paket `demo`.
Signature hasil regenerasi menggunakan salt acak dan boleh berbeda.
