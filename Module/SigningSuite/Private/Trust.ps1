if (-not ('SigningSuite.Native.Trust' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;

namespace SigningSuite.Native
{
    public sealed class EmbeddedSignature
    {
        public int Status;
        public string Message;
        public X509Certificate2 Signer;
        public X509Certificate2 TimestampSigner;
        public bool Timestamped;
    }

    public static class Trust
    {
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct WINTRUST_FILE_INFO
        {
            public uint cbStruct;
            [MarshalAs(UnmanagedType.LPWStr)] public string pcwszFilePath;
            public IntPtr hFile;
            public IntPtr pgKnownSubject;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct WINTRUST_DATA
        {
            public uint cbStruct;
            public IntPtr pPolicyCallbackData;
            public IntPtr pSIPClientData;
            public uint dwUIChoice;
            public uint fdwRevocationChecks;
            public uint dwUnionChoice;
            public IntPtr pFile;
            public uint dwStateAction;
            public IntPtr hWVTStateData;
            public IntPtr pwszURLReference;
            public uint dwProvFlags;
            public uint dwUIContext;
            public IntPtr pSignatureSettings;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct FILETIME
        {
            public uint Low;
            public uint High;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct CRYPT_PROVIDER_SGNR
        {
            public uint cbStruct;
            public FILETIME sftVerifyAsOf;
            public uint csCertChain;
            public IntPtr pasCertChain;
            public uint dwSignerType;
            public IntPtr psSigner;
            public uint dwError;
            public uint csCounterSigners;
            public IntPtr pasCounterSigners;
            public IntPtr pChainContext;
        }

        private const uint WTD_UI_NONE = 2;
        private const uint WTD_REVOKE_NONE = 0;
        private const uint WTD_CHOICE_FILE = 1;
        private const uint WTD_STATEACTION_VERIFY = 1;
        private const uint WTD_STATEACTION_CLOSE = 2;
        private const uint WTD_REVOCATION_CHECK_NONE = 0x10;
        private const uint WTD_CACHE_ONLY_URL_RETRIEVAL = 0x1000;

        [DllImport("wintrust.dll")]
        private static extern int WinVerifyTrust(IntPtr hwnd, ref Guid action, ref WINTRUST_DATA data);

        [DllImport("wintrust.dll")]
        private static extern IntPtr WTHelperProvDataFromStateData(IntPtr hStateData);

        [DllImport("wintrust.dll")]
        private static extern IntPtr WTHelperGetProvSignerFromChain(IntPtr pProvData, uint idxSigner, [MarshalAs(UnmanagedType.Bool)] bool fCounterSigner, uint idxCounterSigner);

        [DllImport("wintrust.dll")]
        private static extern IntPtr WTHelperGetProvCertFromChain(IntPtr pSgnr, uint idxCert);

        private static X509Certificate2 CertificateAt(IntPtr signer)
        {
            if (signer == IntPtr.Zero)
            {
                return null;
            }
            IntPtr providerCert = WTHelperGetProvCertFromChain(signer, 0);
            if (providerCert == IntPtr.Zero)
            {
                return null;
            }
            // CRYPT_PROVIDER_CERT starts with DWORD cbStruct, so pCert sits at the pointer-aligned offset.
            IntPtr context = Marshal.ReadIntPtr(providerCert, IntPtr.Size);
            return context == IntPtr.Zero ? null : new X509Certificate2(context);
        }

        public static EmbeddedSignature VerifyEmbedded(string path)
        {
            // Only the embedded signature is checked: WTD_CHOICE_FILE never consults catalogs, and no revocation or network retrieval happens.
            Guid action = new Guid("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");
            WINTRUST_FILE_INFO fileInfo = new WINTRUST_FILE_INFO();
            fileInfo.cbStruct = (uint)Marshal.SizeOf(typeof(WINTRUST_FILE_INFO));
            fileInfo.pcwszFilePath = path;

            IntPtr filePointer = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(WINTRUST_FILE_INFO)));
            WINTRUST_DATA data = new WINTRUST_DATA();
            EmbeddedSignature result = new EmbeddedSignature();
            try
            {
                Marshal.StructureToPtr(fileInfo, filePointer, false);
                data.cbStruct = (uint)Marshal.SizeOf(typeof(WINTRUST_DATA));
                data.dwUIChoice = WTD_UI_NONE;
                data.fdwRevocationChecks = WTD_REVOKE_NONE;
                data.dwUnionChoice = WTD_CHOICE_FILE;
                data.pFile = filePointer;
                data.dwStateAction = WTD_STATEACTION_VERIFY;
                data.dwProvFlags = WTD_REVOCATION_CHECK_NONE | WTD_CACHE_ONLY_URL_RETRIEVAL;

                result.Status = WinVerifyTrust(IntPtr.Zero, ref action, ref data);
                result.Message = new Win32Exception(result.Status).Message;

                if (data.hWVTStateData != IntPtr.Zero)
                {
                    IntPtr provider = WTHelperProvDataFromStateData(data.hWVTStateData);
                    if (provider != IntPtr.Zero)
                    {
                        IntPtr signer = WTHelperGetProvSignerFromChain(provider, 0, false, 0);
                        result.Signer = CertificateAt(signer);
                        if (signer != IntPtr.Zero)
                        {
                            CRYPT_PROVIDER_SGNR details = (CRYPT_PROVIDER_SGNR)Marshal.PtrToStructure(signer, typeof(CRYPT_PROVIDER_SGNR));
                            if (details.csCounterSigners > 0)
                            {
                                result.Timestamped = true;
                                result.TimestampSigner = CertificateAt(WTHelperGetProvSignerFromChain(provider, 0, true, 0));
                            }
                        }
                    }
                }
            }
            finally
            {
                data.dwStateAction = WTD_STATEACTION_CLOSE;
                WinVerifyTrust(IntPtr.Zero, ref action, ref data);
                Marshal.DestroyStructure(filePointer, typeof(WINTRUST_FILE_INFO));
                Marshal.FreeHGlobal(filePointer);
            }
            return result;
        }
    }
}
'@
}
