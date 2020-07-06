primitive _MD
primitive _MDCTX

primitive EvpMD
  fun null(): (USize, Pointer[_MD]) => (0, @EVP_md_null[Pointer[_MD]]())
  
  fun md2(): (USize, Pointer[_MD]) => (16, @EVP_md2[Pointer[_MD]]())
  fun md4(): (USize, Pointer[_MD]) => (16, @EVP_md4[Pointer[_MD]]())
  fun md5(): (USize, Pointer[_MD]) => (16, @EVP_md5[Pointer[_MD]]())
  fun md5_sha1(): (USize, Pointer[_MD]) => (20, @EVP_md5_sha1[Pointer[_MD]]())

  fun blake2b512(): (USize, Pointer[_MD]) => (64, @EVP_blake2b512[Pointer[_MD]]())
  fun blake2s256(): (USize, Pointer[_MD]) => (32, @EVP_blake2s256[Pointer[_MD]]())

  fun sha1(): (USize, Pointer[_MD]) => (20, @EVP_sha1[Pointer[_MD]]())

  fun sha224(): (USize, Pointer[_MD]) => (28, @EVP_sha224[Pointer[_MD]]())
  fun sha256(): (USize, Pointer[_MD]) => (32, @EVP_sha256[Pointer[_MD]]())
  fun sha384(): (USize, Pointer[_MD]) => (48, @EVP_sha384[Pointer[_MD]]())
  fun sha512(): (USize, Pointer[_MD]) => (64, @EVP_sha512[Pointer[_MD]]())
  fun sha512_224(): (USize, Pointer[_MD]) => (28, @EVP_sha512_224[Pointer[_MD]]())
  fun sha512_256(): (USize, Pointer[_MD]) => (32, @EVP_sha512_256[Pointer[_MD]]())

  fun sha3_224(): (USize, Pointer[_MD]) => (28, @EVP_sha3_224[Pointer[_MD]]())
  fun sha3_256(): (USize, Pointer[_MD]) => (32, @EVP_sha3_256[Pointer[_MD]]())
  fun sha3_384(): (USize, Pointer[_MD]) => (48, @EVP_sha3_384[Pointer[_MD]]())
  fun sha3_512(): (USize, Pointer[_MD]) => (64, @EVP_sha3_512[Pointer[_MD]]())

  fun shake128(): (USize, Pointer[_MD]) => (16, @EVP_shake128[Pointer[_MD]]())
  fun shake256(): (USize, Pointer[_MD]) => (32, @EVP_shake256[Pointer[_MD]]())

  fun mdc2(): (USize, Pointer[_MD]) => (16, @EVP_mdc2[Pointer[_MD]]())

  fun ripemd160(): (USize, Pointer[_MD]) => (20, @EVP_ripemd160[Pointer[_MD]]())

  fun whirlpool(): (USize, Pointer[_MD]) => (64, @EVP_whirlpool[Pointer[_MD]]())

  fun sm3(): (USize, Pointer[_MD]) => (32, @EVP_sm3[Pointer[_MD]]())
