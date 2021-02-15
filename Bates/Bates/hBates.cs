using System;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace Bates
{
    public class hBates
    {
        // Globals
        //-----------
        public static String sDataPipe = "scerpcDSS";          // Sync in dendron & bates
        public static String sControlPipe = "MsFetWid";        // Sync in dendron & bates
        public static String sAESKey = "P8CuaPrgwBjunvZxJcgq"; // Sync in dendron & bates

        // Structs
        //-----------
        [Serializable()]
        [StructLayout(LayoutKind.Sequential)]
        public struct HOOKDAT
        {
            public UInt32 iType;     // 0 == String; 1 == Byte[]; 2 == Fail decrypt; 3 == Fail Data
            public String sHookFunc; // Function where the data originated
            public String sHookData;
            public Byte[] bHookData;
        }

        // Help me!
        //-----------
        public static void getASCII()
        {
            Console.WriteLine(@"   (           )       ");
            Console.WriteLine(@" ( )\     ) ( /(  (    ");
            Console.WriteLine(@" )((_) ( /( )\())))\(  ");
            Console.WriteLine(@"((_)_  )(_)|_))//((_)\ ");
            Console.WriteLine(@" | _ )((_)_| |_(_))((_)");
            Console.WriteLine(@" | _ \/ _` |  _/ -_|_-<");
            Console.WriteLine(@" |___/\__,_|\__\___/__/");
        }

        public static void getHelp()
        {
            string HelpText = "\n >--~~--> Args? <--~~--<\n\n" +
                              "--help      This help menu.\n" +
                              "--listen    Listen for X seconds for Dendron comms.\n" +
                              "--kill      Instruct dendron client to un-hook.\n\n" +
                              " >--~~--> Usage? <--~~--<\n\n" +
                              "# Listen for X seconds on the Dendrobate data pipe\n" +
                              "Bates.exe --listen 180\n\n" +
                              "# Instruct dendron client to un-hook by sending a magic value over the Dendrobate control pipe\n" +
                              "Bates.exe --kill";
            Console.WriteLine(HelpText);
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

        public static void ListenNamedPipe(Int32 iSeconds)
        {
            // Set up a timer
            Stopwatch tTimer = new Stopwatch();
            tTimer.Start();

            Console.WriteLine("\n[+] Creating Bates pipe listener..");
            Console.WriteLine(@"    |_ \\.\pipe\" + sDataPipe);
            Console.WriteLine("    |_ " + iSeconds + "s timer");
            Console.WriteLine("    |_ Waiting for client");

            // Loop
            while (tTimer.Elapsed.TotalSeconds < iSeconds)
            {
                var oPipe = new NamedPipeServerStream(sDataPipe, PipeDirection.InOut, NamedPipeServerStream.MaxAllowedServerInstances, PipeTransmissionMode.Message);
                oPipe.WaitForConnection();
                Byte[] messageBytes = ReadMessage(oPipe);

                // Process data
                HOOKDAT oHook = AESUnKeyObject(messageBytes);
                if (oHook.iType == 2 || oHook.iType == 3)
                {
                    if (oHook.iType == 2)
                    {
                        Console.WriteLine("\n[!] Failed to decrypt pipe data..");
                    } else
                    {
                        Console.WriteLine("\n[!] Invalid data..");
                    }
                } else
                {
                    Console.WriteLine("\n[+] Dendron client connected");
                    Console.WriteLine("    |_ Function  : " + oHook.sHookFunc);
                    if (oHook.iType == 0)
                    {
                        Console.WriteLine("    |_ Data Type : String");
                        Console.WriteLine("    |_ Data      : \n\n" + oHook.sHookData);
                    } else
                    {
                        Console.WriteLine("    |_ Data Type : Byte[]");
                        Console.WriteLine("    |_ Data      : \n\n" + HexDump(oHook.bHookData));
                    }
                }
            }
        }

        public static Boolean passControlCodeByPipe()
        {
            try
            {
                NamedPipeClientStream pipe = new NamedPipeClientStream("localhost", sControlPipe, PipeDirection.InOut);
                try
                {
                    // Can we connect to the pipe?
                    pipe.Connect(50); // Unclear if we need a small ms buffer time here
                    pipe.ReadMode = PipeTransmissionMode.Message;

                    // Encrypt magic data
                    Byte[] bMagic = Encoding.UTF8.GetBytes("Dendrobate");
                    Byte[] bEncrypt = arrayToAESArray(bMagic);

                    // Write data
                    pipe.Write(bEncrypt, 0, bEncrypt.Length);
                    pipe.Close();

                    return true;
                }
                catch
                {
                    pipe.Close();
                    return false;
                }
            }
            catch
            {
                return false;
            }
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

        public static Byte[] arrayToAESArray(Byte[] bInput)
        {
            Byte[][] aSHAKeyMatt = ComputeSha256KeyMat(sAESKey);
            return AES256EncryptToArray(bInput, aSHAKeyMatt[0], aSHAKeyMatt[1]);
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

        public static HOOKDAT ByteArrayToObject(Byte[] arrBytes)
        {
            //--- Array structure
            // [UInt32 Type]--[UInt32 Size]--[UTF8 sFuncName]--[UInt32 Size]--[Byte[] Hook data]
            //---

            // Result object
            HOOKDAT oHookDat = new HOOKDAT();

            // Populate object
            oHookDat.iType = BitConverter.ToUInt32(arrBytes, 0);

            UInt32 iFuncNameSize = BitConverter.ToUInt32(arrBytes, 4);
            oHookDat.sHookFunc = Encoding.UTF8.GetString(arrBytes, 8, (Int32)iFuncNameSize);

            UInt32 iDataSize = BitConverter.ToUInt32(arrBytes, 8 + (Int32)iFuncNameSize);
            if (oHookDat.iType == 0)
            {
                oHookDat.sHookData = Encoding.UTF8.GetString(arrBytes, 12 + (Int32)iFuncNameSize, (Int32)iDataSize);
            } else
            {
                oHookDat.bHookData = new Byte[iDataSize];
                Array.Copy(arrBytes, 12 + (Int32)iFuncNameSize, oHookDat.bHookData, 0, iDataSize);
            }

            return oHookDat;
        }

        public static HOOKDAT AESUnKeyObject(Byte[] bPipeData)
        {
            // Result object
            HOOKDAT oHook = new HOOKDAT();

            // Decrypt
            Byte[][] aSHAKeyMatt = ComputeSha256KeyMat(sAESKey);
            Byte[] bDecrypt = DecryptArrayFromAES256(bPipeData, aSHAKeyMatt[0], aSHAKeyMatt[1]);

            if (bDecrypt.Length > 0)
            {
                try
                {
                    oHook = ByteArrayToObject(bDecrypt);
                } catch
                {
                    oHook.iType = 2;
                }
            }
            else
            {
                oHook.iType = 3;
            }
            return oHook;
        }

        // https://www.codeproject.com/Articles/36747/Quick-and-Dirty-HexDump-of-a-Byte-Array
        public static string HexDump(byte[] bytes, int bytesPerLine = 16)
        {
            if (bytes == null) return "<null>";
            int bytesLength = bytes.Length;

            char[] HexChars = "0123456789ABCDEF".ToCharArray();

            int firstHexColumn =
                  8                   // 8 characters for the address
                + 3;                  // 3 spaces

            int firstCharColumn = firstHexColumn
                + bytesPerLine * 3       // - 2 digit for the hexadecimal value and 1 space
                + (bytesPerLine - 1) / 8 // - 1 extra space every 8 characters from the 9th
                + 2;                  // 2 spaces 

            int lineLength = firstCharColumn
                + bytesPerLine           // - characters to show the ascii value
                + Environment.NewLine.Length; // Carriage return and line feed (should normally be 2)

            char[] line = (new String(' ', lineLength - Environment.NewLine.Length) + Environment.NewLine).ToCharArray();
            int expectedLines = (bytesLength + bytesPerLine - 1) / bytesPerLine;
            StringBuilder result = new StringBuilder(expectedLines * lineLength);

            for (int i = 0; i < bytesLength; i += bytesPerLine)
            {
                line[0] = HexChars[(i >> 28) & 0xF];
                line[1] = HexChars[(i >> 24) & 0xF];
                line[2] = HexChars[(i >> 20) & 0xF];
                line[3] = HexChars[(i >> 16) & 0xF];
                line[4] = HexChars[(i >> 12) & 0xF];
                line[5] = HexChars[(i >> 8) & 0xF];
                line[6] = HexChars[(i >> 4) & 0xF];
                line[7] = HexChars[(i >> 0) & 0xF];

                int hexColumn = firstHexColumn;
                int charColumn = firstCharColumn;

                for (int j = 0; j < bytesPerLine; j++)
                {
                    if (j > 0 && (j & 7) == 0) hexColumn++;
                    if (i + j >= bytesLength)
                    {
                        line[hexColumn] = ' ';
                        line[hexColumn + 1] = ' ';
                        line[charColumn] = ' ';
                    }
                    else
                    {
                        byte b = bytes[i + j];
                        line[hexColumn] = HexChars[(b >> 4) & 0xF];
                        line[hexColumn + 1] = HexChars[b & 0xF];
                        line[charColumn] = (b < 32 ? '·' : (char)b);
                    }
                    hexColumn += 3;
                    charColumn++;
                }
                result.Append(line);
            }
            return result.ToString();
        }
    }
}
