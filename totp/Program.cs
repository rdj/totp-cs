using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

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
// [RFC6238] "TOTP: Time-Based One-Time Password Algorithm"
//    https://datatracker.ietf.org/doc/html/rfc6238
// [RFC4226] "HOTP: An HMAC-Based One-Time Password Algorithm"
//    https://datatracker.ietf.org/doc/html/rfc4226
// [RFC4648] "The Base16, Base32, and Base64 Data Encodings"
//    https://datatracker.ietf.org/doc/html/rfc4648

namespace totp
{
    class Program
    {
        private static readonly string CREDMAN_SERVICE_NAME = // TODO: command line arg
            "ffxiv-totp";
        private const int TIME_STEP_IN_SEC = 30;              // Called "X" in [RFC6238]
        private const long TRUNCATION_MODULUS = 1_000_000;    // Digit = 6 in [RFC4226]
        private static readonly DateTime UNIX_EPOCH =         // Called "T0" in [RFC6238]
            new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);

        // TODO: Use Base32 instead
        static byte[] HexStringToBytes(string hex)
        {
            if ( String.IsNullOrEmpty(hex) || 0 != hex.Length % 2 ) {
                throw new ApplicationException("Bad hex string");
            }
            var result = new byte[hex.Length / 2];
            for ( int i = 0; i < hex.Length / 2; i++ ) {
                result[i] = Convert.ToByte(hex.Substring(2*i, 2), 16);
            }
            return result;
        }

        static void Main(string[] args)
        {
            // Top-level definition from [RFC4226]
            // HOTP(K,C) = Truncate(HMAC-SHA-1(K,C))
            // Extended by [RFC6238]
            // TOTP = HOTP(K,T) where T = (Current Unix time - T0) / X
            var keyString = CredApi.GetPassword(CREDMAN_SERVICE_NAME);
            var key = HexStringToBytes(keyString);

            var elapsedSeconds = DateTime.UtcNow.Subtract(UNIX_EPOCH).TotalSeconds;
            var counter = (long)(elapsedSeconds / TIME_STEP_IN_SEC);
            var counterBytesBE = BitConverter.GetBytes(IPAddress.HostToNetworkOrder(counter));

            var hmac = new HMACSHA1(key).ComputeHash(counterBytesBE);

            // Truncate is described in Sec 5.3 of [RFC4226]. It's not
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
            Console.WriteLine("{0:D6}", totp);
        }
    }
}
