using System;
using System.Net;
using System.Security.Cryptography;

namespace totp
{
    // TOTP is a basic extension of HOTP that replaces the fussy
    // synchronized sequence counter with a simple mechanism based on the
    // current UTC timestamp.
    //
    // The algorithm requires a pre-shared key K, which is commonly
    // established when a service provider displays a QR code
    // encapsulating an otpauth: URI. Users scan the QR code with an app
    // like Google Authenticator, Authy, or 1Password.
    //
    // The otpauth: URI scheme is not formally defined. It was introduced
    // by Google Authenticator and has since been adopted as a de facto
    // standard by apps that wanted to interoperate.
    //
    // The otpauth: URI scheme can be used to provision either HOTP or
    // TOTP authentication, and it includes various future-proofing
    // parameters that are currently ignored, e.g. algorithm.
    //
    // So while in theory there could be a lot of moving parts, at the
    // moment the common practice is to use HMAC-SHA-1, a 30 second
    // counter increment, and 6 digit codes.
    //
    // References:
    //
    // [OTPAUTH] "Key Uri Format"
    //    https://github.com/google/google-authenticator/wiki/Key-Uri-Format
    // [TOTP] RFC 6238 "TOTP: Time-Based One-Time Password Algorithm"
    //    https://datatracker.ietf.org/doc/html/rfc6238
    // [HOTP] RFC 4226 "HOTP: An HMAC-Based One-Time Password Algorithm"
    //    https://datatracker.ietf.org/doc/html/rfc4226
    // [BASENENC] RFC 4648 "The Base16, Base32, and Base64 Data Encodings"
    //    https://datatracker.ietf.org/doc/html/rfc4648
    public class Totp
    {
        // [HOTP] defines "Digit" with a default value of 6. It is
        // used to calculate TRUNCATION_MODULUS = 10^Digit and to zero
        // pad the final decimal representation of the code.
        private static readonly string TRUNCATION_FORMAT = "{0:D6}";
        private const long TRUNCATION_MODULUS = 1_000_000;

        // [TOTP] defines "X" and "T0", which we will call
        // TIME_STEP_IN_SEC and UNIX_EPOCH, respectively.
        private const int TIME_STEP_IN_SEC = 30;
        private static readonly DateTime UNIX_EPOCH = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);

        private readonly byte[] _key;

        public Totp(byte[] key)
        {
            _key = key;
        }

        public string GetCode()
        {
            // HOTP(K,C) = Truncate(HMAC-SHA-1(K,C)) [HOTP]
            return Truncate(ComputeHash(GetCounterBytes()));
        }

        private long GetCounter()
        {
            // TOTP = HOTP(K,T) where T = (Current Unix time - T0) / X [TOTP]
            var elapsedSeconds = DateTime.UtcNow.Subtract(UNIX_EPOCH).TotalSeconds;
            var counter = (long)(elapsedSeconds / TIME_STEP_IN_SEC);
            return counter;
        }

        private byte[] GetCounterBytes()
        {
            // The Key (K), the Counter (C), and Data values are
            // hashed high-order byte first. [HOTP]
            var counterBytesBE = BitConverter.GetBytes(IPAddress.HostToNetworkOrder(GetCounter()));
            return counterBytesBE;
        }

        private byte[] ComputeHash(byte[] counterBytesBE)
        {
            return new HMACSHA1(_key).ComputeHash(counterBytesBE);
        }

        private String Truncate(byte[] hmac)
        {
            // Truncate is described in Sec 5.3 of [HOTP]. It's not
            // really that complicated but the description in the RFC
            // is not necessarily super easy to follow.
            //
            // 1. The input is the 20-byte output of HMAC-SHA-1, in
            //    our case an array with indices [0-19].
            //
            // 2. Treat the low nibble (& 0xf) of the last byte ([19])
            //    as an offset. This will yield a value 0-15 decimal.
            //
            // 3. Starting with that offset, treat the next 4 bytes as
            //    a big-endian integer value, but ignore the most
            //    significant bit. The MSB is ignored so this
            //    procedure will work properly regardless of whether
            //    signed or unsigned integers are used. We end up with
            //    a 4-byte integer formed from the offsets [0-3],
            //    [1-4], ..., [14-17], or [15-18].
            //
            // 4. Get an n-digit code by taking the value mod 10^n,
            //    then examine its decimal representation, including
            //    leading 0s if necessary.

            var offset = hmac[hmac.Length - 1] & 0xf;
            var binCode = BitConverter.ToInt32(hmac, offset);
            var binCodeBE = IPAddress.HostToNetworkOrder(binCode);
            var binCodeBENoSign = binCodeBE & 0x7fffffff;
            var totp = binCodeBENoSign % TRUNCATION_MODULUS;
            return String.Format(TRUNCATION_FORMAT, totp);
        }
    }
}
