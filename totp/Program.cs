using System;

namespace totp
{
    class Program
    {
        private static readonly string CREDMAN_SERVICE_NAME = // TODO: command line arg
            "ffxiv-totp";

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
            var keyString = CredApi.GetPassword(CREDMAN_SERVICE_NAME);
            var key = HexStringToBytes(keyString);
            Console.WriteLine((new Totp(key)).GetCode());
        }
    }
}
