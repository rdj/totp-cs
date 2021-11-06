using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace totp
{
    static class CredApi
    {
        enum CRED_TYPE : int
        {
            GENERIC = 1,
            DOMAIN_PASSWORD = 2,
            DOMAIN_CERTIFICATE = 3,
            DOMAIN_VISIBLE_PASSWORD = 4,
            MAXIMUM = 5
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct CREDENTIAL
        {
            public int flags;
            public int type;
            public IntPtr targetName;
            public IntPtr comment;
            public System.Runtime.InteropServices.ComTypes.FILETIME lastWritten;
            public int credentialBlobSize;
            public IntPtr credentialBlob;
            public int persist;
            public int attributeCount;
            public IntPtr credAttribute;
            public IntPtr targetAlias;
            public IntPtr userName;
        }

        [DllImport("advapi32.dll", EntryPoint = "CredReadW", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern bool CredRead(string target, CRED_TYPE type, int reservedFlag, out IntPtr credentialPtr);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool CredFree([In] IntPtr buffer);

        internal static string GetPassword(string serviceName)
        {
            IntPtr pCred = IntPtr.Zero;
            try {
                if ( !CredRead(serviceName, CRED_TYPE.GENERIC, 0, out pCred) ) {
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "Error from CredRead");
                }
                var cred = Marshal.PtrToStructure<CREDENTIAL>(pCred);
                return Marshal.PtrToStringUni(cred.credentialBlob, cred.credentialBlobSize / 2);
            }
            finally {
                if ( IntPtr.Zero != pCred ) {
                    CredFree(pCred);
                    pCred = IntPtr.Zero;
                }
            }
        }
    }
}
