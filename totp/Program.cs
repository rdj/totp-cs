using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace totp
{
    class Program
    {
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
            var epoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
            var elapsedSeconds = DateTime.UtcNow.Subtract(epoch).TotalSeconds;
            var counter = (long)elapsedSeconds / 30;
            var keyString = CredApi.getPassword("ffxiv-totp");
            var key = HexStringToBytes(keyString);
            var counterBytesBE = BitConverter.GetBytes(IPAddress.HostToNetworkOrder(counter));
            var hmac = new HMACSHA1(key).ComputeHash(counterBytesBE);
            var offset = (uint)hmac[19] & 0xf;
            var binCode = (UInt32)(
                (hmac[offset] & 0x7f) << 24
                | (hmac[offset + 1] & 0xff) << 16
                | (hmac[offset + 2] & 0xff) << 8
                | (hmac[offset + 3] & 0xff));
            var totp = binCode % 1_000_000;
            Console.WriteLine("{0:D6}", totp);
        }
    }
}
