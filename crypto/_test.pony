use "ponytest"

actor Main is TestList
  new create(env: Env) => PonyTest(env, this)
  new make() => None

  fun tag tests(test: PonyTest) =>
    test(_TestConstantTimeCompare)
    test(_TestHash)
    test(_TestDigest)

class iso _TestConstantTimeCompare is UnitTest
  fun name(): String => "crypto/ConstantTimeCompare"

  fun apply(h: TestHelper) =>
    let s1 = "12345"
    let s2 = "54321"
    let s3 = "123456"
    let s4 = "1234"
    let s5 = recover val [as U8: 0; 0; 0; 0; 0] end
    let s6 = String.from_array([0; 0; 0; 0; 0])
    let s7 = ""
    h.assert_true(ConstantTimeCompare(s1, s1))
    h.assert_false(ConstantTimeCompare(s1, s2))
    h.assert_false(ConstantTimeCompare(s1, s3))
    h.assert_false(ConstantTimeCompare(s1, s4))
    h.assert_false(ConstantTimeCompare(s1, s5))
    h.assert_true(ConstantTimeCompare(s5, s6))
    h.assert_false(ConstantTimeCompare(s1, s6))
    h.assert_false(ConstantTimeCompare(s1, s7))

class iso _TestHash is UnitTest
  fun name(): String => "crypto/Hash"

  fun apply(h: TestHelper) =>
    // Message-Digest Algorithm
    // h.assert_eq[String](
      // "dd34716876364a02d0195e2fb9ae2d1b",
      // ToHexString(Hash(EvpMD.md2(), "test")))

    h.assert_eq[String](
      "db346d691d7acc4dc2625db19f9e3f52",
      ToHexString(Hash(EvpMD.md4(), "test")))

    h.assert_eq[String](
      "098f6bcd4621d373cade4e832627b4f6",
      ToHexString(Hash(EvpMD.md5(), "test")))

    h.assert_eq[String](
      "098f6bcd4621d373cade4e832627b4f6a94a8fe5",
      ToHexString(Hash(EvpMD.md5_sha1(), "test")))

    // BLAKE2
    h.assert_eq[String](
      "a71079d42853dea26e453004338670a53814b78137ffbed07603a41d76a483aa" +
      "9bc33b582f77d30a65e6f29a896c0411f38312e1d66e0bf16386c86a89bea572",
      ToHexString(Hash(EvpMD.blake2b512(), "test")))

    h.assert_eq[String](
      "f308fc02ce9172ad02a7d75800ecfc027109bc67987ea32aba9b8dcc7b10150e",
      ToHexString(Hash(EvpMD.blake2s256(), "test")))

    // SHA1
    h.assert_eq[String](
      "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3",
      ToHexString(Hash(EvpMD.sha1(), "test")))

    // SHA2
    h.assert_eq[String](
      "90a3ed9e32b2aaf4c61c410eb925426119e1a9dc53d4286ade99a809",
      ToHexString(Hash(EvpMD.sha224(), "test")))
      
    h.assert_eq[String](
      "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
      ToHexString(Hash(EvpMD.sha256(),"test")))
      
    h.assert_eq[String](
      "768412320f7b0aa5812fce428dc4706b3cae50e02a64caa16a782249bfe8efc4" +
      "b7ef1ccb126255d196047dfedf17a0a9",
      ToHexString(Hash(EvpMD.sha384(), "test")))
      
    h.assert_eq[String](
      "ee26b0dd4af7e749aa1a8ee3c10ae9923f618980772e473f8819a5d4940e0db2" +
      "7ac185f8a0e1d5f84f88bc887fd67b143732c304cc5fa9ad8e6f57f50028a8ff",
      ToHexString(Hash(EvpMD.sha512(), "test")))

    // SHA3 Family
    h.assert_eq[String](
      "3797bf0afbbfca4a7bbba7602a2b552746876517a7f9b7ce2db0ae7b",
      ToHexString(Hash(EvpMD.sha3_224(), "test")))
      
    h.assert_eq[String](
      "36f028580bb02cc8272a9a020f4200e346e276ae664e45ee80745574e2f5ab80",
      ToHexString(Hash(EvpMD.sha3_256(),"test")))
      
    h.assert_eq[String](
      "e516dabb23b6e30026863543282780a3ae0dccf05551cf0295178d7ff0f1b41e" +
      "ecb9db3ff219007c4e097260d58621bd",
      ToHexString(Hash(EvpMD.sha3_384(), "test")))
      
    h.assert_eq[String](
      "9ece086e9bac491fac5c1d1046ca11d737b92a2b2ebd93f005d7b710110c0a67" +
      "8288166e7fbe796883a4f2e9b3ca9f484f521d0ce464345cc1aec96779149c14",
      ToHexString(Hash(EvpMD.sha3_512(), "test")))

    h.assert_eq[String](
      "d3b0aa9cd8b7255622cebc631e867d40",
      ToHexString(Hash(EvpMD.shake128(),"test")))

    h.assert_eq[String](
      "b54ff7255705a71ee2925e4a3e30e41aed489a579d5595e0df13e32e1e4dd202",
      ToHexString(Hash(EvpMD.shake256(),"test")))

    // RIPEMD-160
    h.assert_eq[String](
      "5e52fee47e6b070565f74372468cdc699de89107",
      ToHexString(Hash(EvpMD.ripemd160(), "test")))

    // MDC2
    h.assert_eq[String](
      "c2dd499827c00a40f3e5cfaa22bd4db4",
      ToHexString(Hash(EvpMD.mdc2(), "test")))

    // WHIRLPOOL
    h.assert_eq[String](
      "b913d5bbb8e461c2c5961cbe0edcdadfd29f068225ceb37da6defcf89849368f" +
      "8c6c2eb6a4c4ac75775d032a0ecfdfe8550573062b653fe92fc7b8fb3b7be8d6",
      ToHexString(Hash(EvpMD.whirlpool(),"test")))

    // SM3
    h.assert_eq[String](
      "55e12e91650d2fec56ec74e1d3e4ddbfce2ef3a65890c2a19ecf88a307e76a23",
      ToHexString(Hash(EvpMD.sm3(),"test")))
    
class iso _TestDigest is UnitTest
  fun name(): String => "crypto/Digest"

  fun apply(h: TestHelper) ? =>
    let null = Digest(EvpMD.null())
    null.append("message1")?
    null.append("message2")?
    h.assert_eq[String](
      "",
      ToHexString(null.final()))

    // Message-Digest Algorithm
    let md4 = Digest(EvpMD.md4())
    md4.append("message1")?
    md4.append("message2")?
    h.assert_eq[String](
      "6f299e11a64b5983b932ae9a682f0379",
      ToHexString(md4.final()))

    let md5 = Digest(EvpMD.md5())
    md5.append("message1")?
    md5.append("message2")?
    h.assert_eq[String](
      "94af09c09bb9bb7b5c94fec6e6121482",
      ToHexString(md5.final()))

    let md5_sha1 = Digest(EvpMD.md5_sha1())
    md5_sha1.append("message1")?
    md5_sha1.append("message2")?
    h.assert_eq[String](
      "94af09c09bb9bb7b5c94fec6e6121482942682e2",
      ToHexString(md5_sha1.final()))

    // BLAKE2
    let blake2b512 = Digest(EvpMD.blake2b512())
    blake2b512.append("message1")?
    blake2b512.append("message2")?
    h.assert_eq[String](
      "f0f76859685403fba3d0eb976ea7047621b7003c9c4624e45cb0ee0a281f4a0f" +
      "1abf83e671bcb1beb607fde0510fa55ecbdc3440673669ec06e9a125e6491e58",
      ToHexString(blake2b512.final()))

    let blake2s256 = Digest(EvpMD.blake2s256())
    blake2s256.append("message1")?
    blake2s256.append("message2")?
    h.assert_eq[String](
      "f93b0cbdfd3e056c50d0d6791b42b2b689687be1a6a9de471119bf10393d9af5",
      ToHexString(blake2s256.final()))

    // SHA1
    let sha1 = Digest(EvpMD.sha1())
    sha1.append("message1")?
    sha1.append("message2")?
    h.assert_eq[String](
      "942682e2e49f37b4b224fc1aec1a53a25967e7e0",
      ToHexString(sha1.final()))
      
    //SHA2 Family
    let sha224 = Digest(EvpMD.sha224())
    sha224.append("message1")?
    sha224.append("message2")?
    h.assert_eq[String](
      "fbba013f116e8b09b044b2a785ed7fb6a65ce672d724c1fb20500d45",
      ToHexString(sha224.final()))

    let sha256 = Digest(EvpMD.sha256())
    sha256.append("message1")?
    sha256.append("message2")?
    h.assert_eq[String](
      "68d9b867db4bde630f3c96270b2320a31a72aafbc39997eb2bc9cf2da21e5213",
      ToHexString(sha256.final()))

    let sha384 = Digest(EvpMD.sha384())
    sha384.append("message1")?
    sha384.append("message2")?
    h.assert_eq[String](
      "7736dd67494a7072bf255852bd327406b398cb0b16cb400fcd3fcfb6827d74ab" +
      "9b14673d50515b6273ef15543325f8d3",
      ToHexString(sha384.final()))
      
    let sha512 = Digest(EvpMD.sha512())
    sha512.append("message1")?
    sha512.append("message2")?
    h.assert_eq[String](
      "3511f4825021a90cd55d37db5c3250e6bbcffc9a0d56d88b4e2878ac5b094692" +
      "cd945c6a77006272322f911c9be31fa970043daa4b61cee607566cbfa2c69b09",
       ToHexString(sha512.final()))
        
    // SHA3 Family
    let sha3_224 = Digest(EvpMD.sha3_224())
    sha3_224.append("message1")?
    sha3_224.append("message2")?
    h.assert_eq[String](
      "6e8ddf213865a88369b46d3f711db5c1aeef871b1f79b543cb779361",
      ToHexString(sha3_224.final()))

    let sha3_256 = Digest(EvpMD.sha3_256())
    sha3_256.append("message1")?
    sha3_256.append("message2")?
    h.assert_eq[String](
      "c88b94411c62297f703c137b47338880b8cb27d9f6fc6d973567379989ed4e2f",
      ToHexString(sha3_256.final()))

    let sha3_384 = Digest(EvpMD.sha3_384())
    sha3_384.append("message1")?
    sha3_384.append("message2")?
    h.assert_eq[String](
      "bcdf9e16a94e9aa5c125243c683f32eb5a973a64676b8b84e9ec9d8759851fb8" +
      "eaefc3bba9524aa37514411343c0f7e0",
      ToHexString(sha3_384.final()))
      
    let sha3_512 = Digest(EvpMD.sha3_512())
    sha3_512.append("message1")?
    sha3_512.append("message2")?
    h.assert_eq[String](
      "26ebdee56c0618649b36ec6f494425de17a4e9b22e6fdf629e46b5c158f1180b" +
      "4837b63a00204323dc39c3df0bd6769ba5f0b197ac4f726b60504537eb73473b",
      ToHexString(sha3_512.final()))

    let shake128 = Digest(EvpMD.shake128())
    shake128.append("message1")?
    shake128.append("message2")?
    h.assert_eq[String](
      "0d11671f23b6356bdf4ba8dcae37419d",
      ToHexString(shake128.final()))

    let shake256 = Digest(EvpMD.shake256())
    shake256.append("message1")?
    shake256.append("message2")?
    h.assert_eq[String](
      "80e2bbb14639e3b1fc1df80b47b67fb518b0ed26a1caddfa10d68f7992c33820",
      ToHexString(shake256.final()))

    // MDC2
    let mdc2 = Digest(EvpMD.mdc2())
    mdc2.append("message1")?
    mdc2.append("message2")?
    h.assert_eq[String](
      "173b55f453c4c809b03a3b6dbc6ec912",
      ToHexString(mdc2.final()))

    // RIPEMD-160
    let ripemd160 = Digest(EvpMD.ripemd160())
    ripemd160.append("message1")?
    ripemd160.append("message2")?
    h.assert_eq[String](
      "9813627fca6c51a67ed401cf325c3864cb84ce34",
      ToHexString(ripemd160.final()))

    // WHIRLPOOL
    let whirlpool = Digest(EvpMD.whirlpool())
    whirlpool.append("message1")?
    whirlpool.append("message2")?
    h.assert_eq[String](
      "ebf9861ab64aa70a07dd9b1a8173cc0dc1323b4c989283394ea07be48c284f94" +
      "5e868df989aad6eaf400e2cdcd85d089402529803759a81c8e41f97b7ee0a253",
      ToHexString(whirlpool.final()))

    // SM3
    let sm3 = Digest(EvpMD.sm3())
    sm3.append("message1")?
    sm3.append("message2")?
    h.assert_eq[String](
      "39e2180230837cd17b1773b888be75caa7c228eff95f6662d682a475127d6379",
      ToHexString(sm3.final()))

