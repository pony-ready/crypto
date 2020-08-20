primitive _MD
primitive _MDCTX

primitive EvpMD
  fun null(): (USize, Pointer[_MD]) => (0, @EVP_md_null[Pointer[_MD]]())
    
  // Message digest
  fun md2(): (USize, Pointer[_MD]) => (16, @EVP_md2[Pointer[_MD]]())
  fun md4(): (USize, Pointer[_MD]) => (16, @EVP_md4[Pointer[_MD]]())
  fun md5(): (USize, Pointer[_MD]) => (16, @EVP_md5[Pointer[_MD]]())
  fun md5_sha1(): (USize, Pointer[_MD]) => (20, @EVP_md5_sha1[Pointer[_MD]]())

  // BLAKE2
  fun blake2b512(): (USize, Pointer[_MD]) => (64, @EVP_blake2b512[Pointer[_MD]]())
  fun blake2s256(): (USize, Pointer[_MD]) => (32, @EVP_blake2s256[Pointer[_MD]]())

  fun sha1(): (USize, Pointer[_MD]) => (20, @EVP_sha1[Pointer[_MD]]())

  // SHA2 Family
  fun sha224(): (USize, Pointer[_MD]) => (28, @EVP_sha224[Pointer[_MD]]())
  fun sha256(): (USize, Pointer[_MD]) => (32, @EVP_sha256[Pointer[_MD]]())
  fun sha384(): (USize, Pointer[_MD]) => (48, @EVP_sha384[Pointer[_MD]]())
  fun sha512(): (USize, Pointer[_MD]) => (64, @EVP_sha512[Pointer[_MD]]())
  fun sha512_224(): (USize, Pointer[_MD]) => (28, @EVP_sha512_224[Pointer[_MD]]())
  fun sha512_256(): (USize, Pointer[_MD]) => (32, @EVP_sha512_256[Pointer[_MD]]())

  // SHA3 Family
  fun sha3_224(): (USize, Pointer[_MD]) => (28, @EVP_sha3_224[Pointer[_MD]]())
  fun sha3_256(): (USize, Pointer[_MD]) => (32, @EVP_sha3_256[Pointer[_MD]]())
  fun sha3_384(): (USize, Pointer[_MD]) => (48, @EVP_sha3_384[Pointer[_MD]]())
  fun sha3_512(): (USize, Pointer[_MD]) => (64, @EVP_sha3_512[Pointer[_MD]]())
  fun shake128(): (USize, Pointer[_MD]) => (16, @EVP_shake128[Pointer[_MD]]())
  fun shake256(): (USize, Pointer[_MD]) => (32, @EVP_shake256[Pointer[_MD]]())

  // OTHER
  fun mdc2(): (USize, Pointer[_MD]) => (16, @EVP_mdc2[Pointer[_MD]]())

  fun ripemd160(): (USize, Pointer[_MD]) => (20, @EVP_ripemd160[Pointer[_MD]]())

  fun whirlpool(): (USize, Pointer[_MD]) => (64, @EVP_whirlpool[Pointer[_MD]]())

  fun sm3(): (USize, Pointer[_MD]) => (32, @EVP_sm3[Pointer[_MD]]())

primitive _CIPHERCTX
primitive _CIPHER

primitive EvpCipher
  fun nec_null(): Pointer[_CIPHER] => @EVP_enc_null[Pointer[_CIPHER]]()

  // DES
  fun des_ecb(): Pointer[_CIPHER] => @EVP_des_ecb[Pointer[_CIPHER]]()
  fun des_ede(): Pointer[_CIPHER] => @EVP_des_ede[Pointer[_CIPHER]]()
  fun des_ede3(): Pointer[_CIPHER] => @EVP_des_ede3[Pointer[_CIPHER]]()
  fun des_ede_ecb(): Pointer[_CIPHER] => @EVP_des_ede_ecb[Pointer[_CIPHER]]()
  fun des_ede3_ecb(): Pointer[_CIPHER] => @EVP_des_ede3_ecb[Pointer[_CIPHER]]()
  fun des_cfb64(): Pointer[_CIPHER] => @EVP_des_cfb64[Pointer[_CIPHER]]()
  // #  define EVP_des_cfb EVP_des_cfb64
  fun des_cfb1(): Pointer[_CIPHER] => @EVP_des_cfb1[Pointer[_CIPHER]]()
  fun des_cfb8(): Pointer[_CIPHER] => @EVP_des_cfb8[Pointer[_CIPHER]]()
  fun des_ede_cfb64(): Pointer[_CIPHER] => @EVP_des_ede_cfb64[Pointer[_CIPHER]]()
  // #  define EVP_des_ede_cfb EVP_des_ede_cfb64
  fun des_ede3_cfb64(): Pointer[_CIPHER] => @EVP_des_ede3_cfb64[Pointer[_CIPHER]]()
  // #  define EVP_des_ede3_cfb EVP_des_ede3_cfb64
  fun des_ede3_cfb1(): Pointer[_CIPHER] => @EVP_des_ede3_cfb1[Pointer[_CIPHER]]()
  fun des_ede3_cfb8(): Pointer[_CIPHER] => @EVP_des_ede3_cfb8[Pointer[_CIPHER]]()
  fun des_ofb(): Pointer[_CIPHER] => @EVP_des_ofb[Pointer[_CIPHER]]()
  fun des_ede_ofb(): Pointer[_CIPHER] => @EVP_des_ede_ofb[Pointer[_CIPHER]]()
  fun des_ede3_ofb(): Pointer[_CIPHER] => @EVP_des_ede3_ofb[Pointer[_CIPHER]]()
  fun des_cbc(): Pointer[_CIPHER] => @EVP_des_cbc[Pointer[_CIPHER]]()
  fun des_ede_cbc(): Pointer[_CIPHER] => @EVP_des_ede_cbc[Pointer[_CIPHER]]()
  fun des_ede3_cbc(): Pointer[_CIPHER] => @EVP_des_ede3_cbc[Pointer[_CIPHER]]()
  fun desx_cbc(): Pointer[_CIPHER] => @EVP_desx_cbc[Pointer[_CIPHER]]()
  fun des_ede3_wrap(): Pointer[_CIPHER] => @EVP_des_ede3_wrap[Pointer[_CIPHER]]()

  // RC4
  fun rc4(): Pointer[_CIPHER] => @EVP_rc4[Pointer[_CIPHER]]()
  fun rc4_40(): Pointer[_CIPHER] => @EVP_rc4_40[Pointer[_CIPHER]]()
  fun rc4_hmac_md5(): Pointer[_CIPHER] => @EVP_rc4_hmac_md5[Pointer[_CIPHER]]()
  
  // IDEA
  fun idea_ecb(): Pointer[_CIPHER] => @EVP_idea_ecb[Pointer[_CIPHER]]()
  fun idea_cfb64(): Pointer[_CIPHER] => @EVP_idea_cfb64[Pointer[_CIPHER]]()
  // #  define EVP_idea_cfb EVP_idea_cfb64
  fun idea_ofb(): Pointer[_CIPHER] => @EVP_idea_ofb[Pointer[_CIPHER]]()
  fun idea_cbc(): Pointer[_CIPHER] => @EVP_idea_cbc[Pointer[_CIPHER]]()
  
  // RC2
  fun rc2_ecb(): Pointer[_CIPHER] => @EVP_rc2_ecb[Pointer[_CIPHER]]()
  fun rc2_cbc(): Pointer[_CIPHER] => @EVP_rc2_cbc[Pointer[_CIPHER]]()
  fun rc2_40_cbc(): Pointer[_CIPHER] => @EVP_rc2_40_cbc[Pointer[_CIPHER]]()
  fun rc2_64_cbc(): Pointer[_CIPHER] => @EVP_rc2_64_cbc[Pointer[_CIPHER]]()
  fun rc2_cfb64(): Pointer[_CIPHER] => @EVP_rc2_cfb64[Pointer[_CIPHER]]()
  // #  define EVP_rc2_cfb EVP_rc2_cfb64
  fun rc2_ofb(): Pointer[_CIPHER] => @EVP_rc2_ofb[Pointer[_CIPHER]]()
  
  // BF
  fun bf_ecb(): Pointer[_CIPHER] => @EVP_bf_ecb[Pointer[_CIPHER]]()
  fun bf_cbc(): Pointer[_CIPHER] => @EVP_bf_cbc[Pointer[_CIPHER]]()
  fun bf_cfb64(): Pointer[_CIPHER] => @EVP_bf_cfb64[Pointer[_CIPHER]]()
  // #  define EVP_bf_cfb EVP_bf_cfb64
  fun bf_ofb(): Pointer[_CIPHER] => @EVP_bf_ofb[Pointer[_CIPHER]]()
  
  // CAST
  fun cast5_ecb(): Pointer[_CIPHER] => @EVP_cast5_ecb[Pointer[_CIPHER]]()
  fun cast5_cbc(): Pointer[_CIPHER] => @EVP_cast5_cbc[Pointer[_CIPHER]]()
  fun cast5_cfb64(): Pointer[_CIPHER] => @EVP_cast5_cfb64[Pointer[_CIPHER]]()
  // #  define EVP_cast5_cfb EVP_cast5_cfb64
  fun cast5_ofb(): Pointer[_CIPHER] => @EVP_cast5_ofb[Pointer[_CIPHER]]()
  
  // RC5
  fun rc5_32_12_16_cbc(): Pointer[_CIPHER] => @EVP_rc5_32_12_16_cbc[Pointer[_CIPHER]]()
  fun rc5_32_12_16_ecb(): Pointer[_CIPHER] => @EVP_rc5_32_12_16_ecb[Pointer[_CIPHER]]()
  fun rc5_32_12_16_cfb64(): Pointer[_CIPHER] => @EVP_rc5_32_12_16_cfb64[Pointer[_CIPHER]]()
  // #  define EVP_rc5_32_12_16_cfb EVP_rc5_32_12_16_cfb64
  fun rc5_32_12_16_ofb(): Pointer[_CIPHER] => @EVP_rc5_32_12_16_ofb[Pointer[_CIPHER]]()
  
  // AES
  fun aes_128_ecb(): Pointer[_CIPHER] => @EVP_aes_128_ecb[Pointer[_CIPHER]]()
  fun aes_128_cbc(): Pointer[_CIPHER] => @EVP_aes_128_cbc[Pointer[_CIPHER]]()
  fun aes_128_cfb1(): Pointer[_CIPHER] => @EVP_aes_128_cfb1[Pointer[_CIPHER]]()
  fun aes_128_cfb8(): Pointer[_CIPHER] => @EVP_aes_128_cfb8[Pointer[_CIPHER]]()
  fun aes_128_cfb128(): Pointer[_CIPHER] => @EVP_aes_128_cfb128[Pointer[_CIPHER]]()
  // # define EVP_aes_128_cfb EVP_aes_128_cfb128
  fun aes_128_ofb(): Pointer[_CIPHER] => @EVP_aes_128_ofb[Pointer[_CIPHER]]()
  fun aes_128_ctr(): Pointer[_CIPHER] => @EVP_aes_128_ctr[Pointer[_CIPHER]]()
  fun aes_128_ccm(): Pointer[_CIPHER] => @EVP_aes_128_ccm[Pointer[_CIPHER]]()
  fun aes_128_gcm(): Pointer[_CIPHER] => @EVP_aes_128_gcm[Pointer[_CIPHER]]()
  fun aes_128_xts(): Pointer[_CIPHER] => @EVP_aes_128_xts[Pointer[_CIPHER]]()
  fun aes_128_wrap(): Pointer[_CIPHER] => @EVP_aes_128_wrap[Pointer[_CIPHER]]()
  fun aes_128_wrap_pad(): Pointer[_CIPHER] => @EVP_aes_128_wrap_pad[Pointer[_CIPHER]]()
  fun aes_128_ocb(): Pointer[_CIPHER] => @EVP_aes_128_ocb[Pointer[_CIPHER]]()
  fun aes_192_ecb(): Pointer[_CIPHER] => @EVP_aes_192_ecb[Pointer[_CIPHER]]()
  fun aes_192_cbc(): Pointer[_CIPHER] => @EVP_aes_192_cbc[Pointer[_CIPHER]]()
  fun aes_192_cfb1(): Pointer[_CIPHER] => @EVP_aes_192_cfb1[Pointer[_CIPHER]]()
  fun aes_192_cfb8(): Pointer[_CIPHER] => @EVP_aes_192_cfb8[Pointer[_CIPHER]]()
  fun aes_192_cfb128(): Pointer[_CIPHER] => @EVP_aes_192_cfb128[Pointer[_CIPHER]]()
  // # define EVP_aes_192_cfb EVP_aes_192_cfb128
  fun aes_192_ofb(): Pointer[_CIPHER] => @EVP_aes_192_ofb[Pointer[_CIPHER]]()
  fun aes_192_ctr(): Pointer[_CIPHER] => @EVP_aes_192_ctr[Pointer[_CIPHER]]()
  fun aes_192_ccm(): Pointer[_CIPHER] => @EVP_aes_192_ccm[Pointer[_CIPHER]]()
  fun aes_192_gcm(): Pointer[_CIPHER] => @EVP_aes_192_gcm[Pointer[_CIPHER]]()
  fun aes_192_wrap(): Pointer[_CIPHER] => @EVP_aes_192_wrap[Pointer[_CIPHER]]()
  fun aes_192_wrap_pad(): Pointer[_CIPHER] => @EVP_aes_192_wrap_pad[Pointer[_CIPHER]]()
  fun aes_192_ocb(): Pointer[_CIPHER] => @EVP_aes_192_ocb[Pointer[_CIPHER]]()
  fun aes_256_ecb(): Pointer[_CIPHER] => @EVP_aes_256_ecb[Pointer[_CIPHER]]()
  fun aes_256_cbc(): Pointer[_CIPHER] => @EVP_aes_256_cbc[Pointer[_CIPHER]]()
  fun aes_256_cfb1(): Pointer[_CIPHER] => @EVP_aes_256_cfb1[Pointer[_CIPHER]]()
  fun aes_256_cfb8(): Pointer[_CIPHER] => @EVP_aes_256_cfb8[Pointer[_CIPHER]]()
  fun aes_256_cfb128(): Pointer[_CIPHER] => @EVP_aes_256_cfb128[Pointer[_CIPHER]]()
  // # define EVP_aes_256_cfb EVP_aes_256_cfb128
  fun aes_256_ofb(): Pointer[_CIPHER] => @EVP_aes_256_ofb[Pointer[_CIPHER]]()
  fun aes_256_ctr(): Pointer[_CIPHER] => @EVP_aes_256_ctr[Pointer[_CIPHER]]()
  fun aes_256_ccm(): Pointer[_CIPHER] => @EVP_aes_256_ccm[Pointer[_CIPHER]]()
  fun aes_256_gcm(): Pointer[_CIPHER] => @EVP_aes_256_gcm[Pointer[_CIPHER]]()
  fun aes_256_xts(): Pointer[_CIPHER] => @EVP_aes_256_xts[Pointer[_CIPHER]]()
  fun aes_256_wrap(): Pointer[_CIPHER] => @EVP_aes_256_wrap[Pointer[_CIPHER]]()
  fun aes_256_wrap_pad(): Pointer[_CIPHER] => @EVP_aes_256_wrap_pad[Pointer[_CIPHER]]()
  fun aes_256_ocb(): Pointer[_CIPHER] => @EVP_aes_256_ocb[Pointer[_CIPHER]]()
  fun aes_128_cbc_hmac_sha1(): Pointer[_CIPHER] => @EVP_aes_128_cbc_hmac_sha1[Pointer[_CIPHER]]()
  fun aes_256_cbc_hmac_sha1(): Pointer[_CIPHER] => @EVP_aes_256_cbc_hmac_sha1[Pointer[_CIPHER]]()
  fun aes_128_cbc_hmac_sha256(): Pointer[_CIPHER] => @EVP_aes_128_cbc_hmac_sha256[Pointer[_CIPHER]]()
  fun aes_256_cbc_hmac_sha256(): Pointer[_CIPHER] => @EVP_aes_256_cbc_hmac_sha256[Pointer[_CIPHER]]()
  fun aes_128_siv(): Pointer[_CIPHER] => @EVP_aes_128_siv[Pointer[_CIPHER]]()
  fun aes_192_siv(): Pointer[_CIPHER] => @EVP_aes_192_siv[Pointer[_CIPHER]]()
  fun aes_256_siv(): Pointer[_CIPHER] => @EVP_aes_256_siv[Pointer[_CIPHER]]()
  
  // ARIA
  fun aria_128_ecb(): Pointer[_CIPHER] => @EVP_aria_128_ecb[Pointer[_CIPHER]]()
  fun aria_128_cbc(): Pointer[_CIPHER] => @EVP_aria_128_cbc[Pointer[_CIPHER]]()
  fun aria_128_cfb1(): Pointer[_CIPHER] => @EVP_aria_128_cfb1[Pointer[_CIPHER]]()
  fun aria_128_cfb8(): Pointer[_CIPHER] => @EVP_aria_128_cfb8[Pointer[_CIPHER]]()
  fun aria_128_cfb128(): Pointer[_CIPHER] => @EVP_aria_128_cfb128[Pointer[_CIPHER]]()
  // #  define EVP_aria_128_cfb EVP_aria_128_cfb128
  fun aria_128_ctr(): Pointer[_CIPHER] => @EVP_aria_128_ctr[Pointer[_CIPHER]]()
  fun aria_128_ofb(): Pointer[_CIPHER] => @EVP_aria_128_ofb[Pointer[_CIPHER]]()
  fun aria_128_gcm(): Pointer[_CIPHER] => @EVP_aria_128_gcm[Pointer[_CIPHER]]()
  fun aria_128_ccm(): Pointer[_CIPHER] => @EVP_aria_128_ccm[Pointer[_CIPHER]]()
  fun aria_192_ecb(): Pointer[_CIPHER] => @EVP_aria_192_ecb[Pointer[_CIPHER]]()
  fun aria_192_cbc(): Pointer[_CIPHER] => @EVP_aria_192_cbc[Pointer[_CIPHER]]()
  fun aria_192_cfb1(): Pointer[_CIPHER] => @EVP_aria_192_cfb1[Pointer[_CIPHER]]()
  fun aria_192_cfb8(): Pointer[_CIPHER] => @EVP_aria_192_cfb8[Pointer[_CIPHER]]()
  fun aria_192_cfb128(): Pointer[_CIPHER] => @EVP_aria_192_cfb128[Pointer[_CIPHER]]()
  // #  define EVP_aria_192_cfb EVP_aria_192_cfb128
  fun aria_192_ctr(): Pointer[_CIPHER] => @EVP_aria_192_ctr[Pointer[_CIPHER]]()
  fun aria_192_ofb(): Pointer[_CIPHER] => @EVP_aria_192_ofb[Pointer[_CIPHER]]()
  fun aria_192_gcm(): Pointer[_CIPHER] => @EVP_aria_192_gcm[Pointer[_CIPHER]]()
  fun aria_192_ccm(): Pointer[_CIPHER] => @EVP_aria_192_ccm[Pointer[_CIPHER]]()
  fun aria_256_ecb(): Pointer[_CIPHER] => @EVP_aria_256_ecb[Pointer[_CIPHER]]()
  fun aria_256_cbc(): Pointer[_CIPHER] => @EVP_aria_256_cbc[Pointer[_CIPHER]]()
  fun aria_256_cfb1(): Pointer[_CIPHER] => @EVP_aria_256_cfb1[Pointer[_CIPHER]]()
  fun aria_256_cfb8(): Pointer[_CIPHER] => @EVP_aria_256_cfb8[Pointer[_CIPHER]]()
  fun aria_256_cfb128(): Pointer[_CIPHER] => @EVP_aria_256_cfb128[Pointer[_CIPHER]]()
  // #  define EVP_aria_256_cfb EVP_aria_256_cfb128
  fun aria_256_ctr(): Pointer[_CIPHER] => @EVP_aria_256_ctr[Pointer[_CIPHER]]()
  fun aria_256_ofb(): Pointer[_CIPHER] => @EVP_aria_256_ofb[Pointer[_CIPHER]]()
  fun aria_256_gcm(): Pointer[_CIPHER] => @EVP_aria_256_gcm[Pointer[_CIPHER]]()
  fun aria_256_ccm(): Pointer[_CIPHER] => @EVP_aria_256_ccm[Pointer[_CIPHER]]()
  
  // CAMELLIA
  fun camellia_128_ecb(): Pointer[_CIPHER] => @EVP_camellia_128_ecb[Pointer[_CIPHER]]()
  fun camellia_128_cbc(): Pointer[_CIPHER] => @EVP_camellia_128_cbc[Pointer[_CIPHER]]()
  fun camellia_128_cfb1(): Pointer[_CIPHER] => @EVP_camellia_128_cfb1[Pointer[_CIPHER]]()
  fun camellia_128_cfb8(): Pointer[_CIPHER] => @EVP_camellia_128_cfb8[Pointer[_CIPHER]]()
  fun camellia_128_cfb128(): Pointer[_CIPHER] => @EVP_camellia_128_cfb128[Pointer[_CIPHER]]()
  // #  define EVP_camellia_128_cfb EVP_camellia_128_cfb128
  fun camellia_128_ofb(): Pointer[_CIPHER] => @EVP_camellia_128_ofb[Pointer[_CIPHER]]()
  fun camellia_128_ctr(): Pointer[_CIPHER] => @EVP_camellia_128_ctr[Pointer[_CIPHER]]()
  fun camellia_192_ecb(): Pointer[_CIPHER] => @EVP_camellia_192_ecb[Pointer[_CIPHER]]()
  fun camellia_192_cbc(): Pointer[_CIPHER] => @EVP_camellia_192_cbc[Pointer[_CIPHER]]()
  fun camellia_192_cfb1(): Pointer[_CIPHER] => @EVP_camellia_192_cfb1[Pointer[_CIPHER]]()
  fun camellia_192_cfb8(): Pointer[_CIPHER] => @EVP_camellia_192_cfb8[Pointer[_CIPHER]]()
  fun camellia_192_cfb128(): Pointer[_CIPHER] => @EVP_camellia_192_cfb128[Pointer[_CIPHER]]()
  // #  define EVP_camellia_192_cfb EVP_camellia_192_cfb128
  fun camellia_192_ofb(): Pointer[_CIPHER] => @EVP_camellia_192_ofb[Pointer[_CIPHER]]()
  fun camellia_192_ctr(): Pointer[_CIPHER] => @EVP_camellia_192_ctr[Pointer[_CIPHER]]()
  fun camellia_256_ecb(): Pointer[_CIPHER] => @EVP_camellia_256_ecb[Pointer[_CIPHER]]()
  fun camellia_256_cbc(): Pointer[_CIPHER] => @EVP_camellia_256_cbc[Pointer[_CIPHER]]()
  fun camellia_256_cfb1(): Pointer[_CIPHER] => @EVP_camellia_256_cfb1[Pointer[_CIPHER]]()
  fun camellia_256_cfb8(): Pointer[_CIPHER] => @EVP_camellia_256_cfb8[Pointer[_CIPHER]]()
  fun camellia_256_cfb128(): Pointer[_CIPHER] => @EVP_camellia_256_cfb128[Pointer[_CIPHER]]()
  // #  define EVP_camellia_256_cfb EVP_camellia_256_cfb128
  fun camellia_256_ofb(): Pointer[_CIPHER] => @EVP_camellia_256_ofb[Pointer[_CIPHER]]()
  fun camellia_256_ctr(): Pointer[_CIPHER] => @EVP_camellia_256_ctr[Pointer[_CIPHER]]()

  // CHACHA
  fun chacha20(): Pointer[_CIPHER] => @EVP_chacha20[Pointer[_CIPHER]]()
  // #  ifndef OPENSSL_NO_POLY1305
  fun chacha20_poly1305(): Pointer[_CIPHER] => @EVP_chacha20_poly1305[Pointer[_CIPHER]]()

  // SEED
  fun seed_ecb(): Pointer[_CIPHER] => @EVP_seed_ecb[Pointer[_CIPHER]]()
  fun seed_cbc(): Pointer[_CIPHER] => @EVP_seed_cbc[Pointer[_CIPHER]]()
  fun seed_cfb128(): Pointer[_CIPHER] => @EVP_seed_cfb128[Pointer[_CIPHER]]()
  // #  define EVP_seed_cfb EVP_seed_cfb128
  fun seed_ofb(): Pointer[_CIPHER] => @EVP_seed_ofb[Pointer[_CIPHER]]()

  // SM4
  fun sm4_ecb(): Pointer[_CIPHER] => @EVP_sm4_ecb[Pointer[_CIPHER]]()
  fun sm4_cbc(): Pointer[_CIPHER] => @EVP_sm4_cbc[Pointer[_CIPHER]]()
  fun sm4_cfb128(): Pointer[_CIPHER] => @EVP_sm4_cfb128[Pointer[_CIPHER]]()
  // #  define EVP_sm4_cfb EVP_sm4_cfb128
  fun sm4_ofb(): Pointer[_CIPHER] => @EVP_sm4_ofb[Pointer[_CIPHER]]()
  fun sm4_ctr(): Pointer[_CIPHER] => @EVP_sm4_ctr[Pointer[_CIPHER]]()
