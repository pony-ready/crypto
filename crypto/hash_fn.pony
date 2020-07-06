use "path:/usr/local/opt/libressl/lib" if osx
use "lib:crypto"

use "format"

primitive Hash
  fun tag apply(md: (USize, Pointer[_MD]), input: ByteSeq): Array[U8] val => 
    let digest_size = md._1
    let digest_func = md._2
    let ctx = @EVP_MD_CTX_new[Pointer[_MDCTX]]()
    let digest =
      recover String.from_cpointer(
        @pony_alloc[Pointer[U8]](@pony_ctx[Pointer[None] iso](), digest_size), digest_size)
      end
      
    @EVP_DigestInit_ex[None](ctx, digest_func, USize(0))
    @EVP_DigestUpdate[None](ctx, input.cpointer(), input.size())
    @EVP_DigestFinal_ex[None](ctx, digest.cpointer(), Pointer[USize])
    @EVP_MD_CTX_free[None](ctx)

    (consume digest).array()

class Digest
  """
  Produces a fixed-length byte array based on the input sequence.
  """
  let _digest_size: USize
  let _digest_func: Pointer[_MD]
  let _ctx: Pointer[_MDCTX]
  var _hash: (Array[U8] val | None) = None

  new create(md: (USize, Pointer[_MD val] ref)) =>
    _digest_size = md._1
    _digest_func = md._2
    _ctx = @EVP_MD_CTX_new[Pointer[_MDCTX]]()
    @EVP_DigestInit_ex[None](_ctx, _digest_func, USize(0))
  
  fun ref apply(input: ByteSeq) ? =>
    """
    Update the Digest object with input. Throw an error if final() has been
    called.
    """
    append(input) ?

  fun ref append(input: ByteSeq) ? =>
    """
    Update the Digest object with input. Throw an error if final() has been
    called.
    """
    if _hash isnt None then error end
    @EVP_DigestUpdate[None](_ctx, input.cpointer(), input.size())

  fun ref final(): Array[U8] val =>
    """
    Return the digest of the strings passed to the append() method.
    """
    match _hash
    | let h: Array[U8] val => h
    else
      let size = _digest_size
      let digest =
        recover String.from_cpointer(
          @pony_alloc[Pointer[U8]](@pony_ctx[Pointer[None] iso](), size), size)
        end
      @EVP_DigestFinal_ex[None](_ctx, digest.cpointer(), Pointer[USize])
      @EVP_MD_CTX_free[None](_ctx)
      let h = (consume digest).array()
      _hash = h
      h
    end

  fun digest_size(): USize =>
    """
    Return the size of the message digest in bytes.
    """
    _digest_size

/*
primitive MD4 is HashFn
  fun tag apply(input: ByteSeq): Array[U8] val =>
    """
    Compute the MD4 message digest conforming to RFC 1320
    """
    recover
      let size: USize = 16
      let digest =
        @pony_alloc[Pointer[U8]](@pony_ctx[Pointer[None] iso](), size)
      @MD4[Pointer[U8]](input.cpointer(), input.size(), digest)
      Array[U8].from_cpointer(digest, size)
    end

primitive MD5 is HashFn
  fun tag apply(input: ByteSeq): Array[U8] val =>
    """
    Compute the MD5 message digest conforming to RFC 1321
    """
    recover
      let size: USize = 16
      let digest =
        @pony_alloc[Pointer[U8]](@pony_ctx[Pointer[None] iso](), size)
      @MD5[Pointer[U8]](input.cpointer(), input.size(), digest)
      Array[U8].from_cpointer(digest, size)
    end

primitive RIPEMD160 is HashFn
  fun tag apply(input: ByteSeq): Array[U8] val =>
    """
    Compute the RIPEMD160 message digest conforming to ISO/IEC 10118-3
    """
    recover
      let size: USize = 20
      let digest =
        @pony_alloc[Pointer[U8]](@pony_ctx[Pointer[None] iso](), size)
      @RIPEMD160[Pointer[U8]](input.cpointer(), input.size(), digest)
      Array[U8].from_cpointer(digest, size)
    end

primitive SHA1 is HashFn
  fun tag apply(input: ByteSeq): Array[U8] val =>
    """
    Compute the SHA1 message digest conforming to US Federal Information
    Processing Standard FIPS PUB 180-4
    """
    recover
      let size: USize = 20
      let digest =
        @pony_alloc[Pointer[U8]](@pony_ctx[Pointer[None] iso](), size)
      @SHA1[Pointer[U8]](input.cpointer(), input.size(), digest)
      Array[U8].from_cpointer(digest, size)
    end

primitive SHA224 is HashFn
  fun tag apply(input: ByteSeq): Array[U8] val =>
    """
    Compute the SHA224 message digest conforming to US Federal Information
    Processing Standard FIPS PUB 180-4
    """
    recover
      let size: USize = 28
      let digest =
        @pony_alloc[Pointer[U8]](@pony_ctx[Pointer[None] iso](), size)
      @SHA224[Pointer[U8]](input.cpointer(), input.size(), digest)
      Array[U8].from_cpointer(digest, size)
    end

primitive SHA256 is HashFn
  fun tag apply(input: ByteSeq): Array[U8] val =>
    """
    Compute the SHA256 message digest conforming to US Federal Information
    Processing Standard FIPS PUB 180-4
    """
    recover
      let size: USize = 32
      let digest =
        @pony_alloc[Pointer[U8]](@pony_ctx[Pointer[None] iso](), size)
      @SHA256[Pointer[U8]](input.cpointer(), input.size(), digest)
      Array[U8].from_cpointer(digest, size)
    end

primitive SHA384 is HashFn
  fun tag apply(input: ByteSeq): Array[U8] val =>
    """
    Compute the SHA384 message digest conforming to US Federal Information
    Processing Standard FIPS PUB 180-4
    """
    recover
      let size: USize = 48
      let digest =
        @pony_alloc[Pointer[U8]](@pony_ctx[Pointer[None] iso](), size)
      @SHA384[Pointer[U8]](input.cpointer(), input.size(), digest)
      Array[U8].from_cpointer(digest, size)
    end

primitive SHA512 is HashFn
  fun tag apply(input: ByteSeq): Array[U8] val =>
    """
    Compute the SHA512 message digest conforming to US Federal Information
    Processing Standard FIPS PUB 180-4
    """
    recover
      let size: USize = 64
      let digest =
        @pony_alloc[Pointer[U8]](@pony_ctx[Pointer[None] iso](), size)
      @SHA512[Pointer[U8]](input.cpointer(), input.size(), digest)
      Array[U8].from_cpointer(digest, size)
    end
*/
primitive ToHexString
  fun tag apply(bs: Array[U8] val): String =>
    """
    Return the lower-case hexadecimal string representation of the given Array
    of U8.
    """
    let out = recover String(bs.size() * 2) end
    for c in bs.values() do
      out.append(Format.int[U8](c where
        fmt = FormatHexSmallBare, width = 2, fill = '0'))
    end
    consume out

