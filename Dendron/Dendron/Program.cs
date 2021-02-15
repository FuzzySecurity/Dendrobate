using System;
using System.Runtime.InteropServices;
using System.Threading;
using System.Windows.Forms;

namespace Dendron
{
    class Program
    {
        // Install Hooks
        //-----------
        public static void CreateFileWHook()
        {
            // Create new native function hook
            var nHook = oleaccrt.LocalHook.Create(
                oleaccrt.LocalHook.GetProcAddress("KernelBase.dll", "CreateFileW"),
                new API.DELEGATES.CreateFileW(CreateFileWDetour),
                null);

            // Add hook to global hook list
            hDendron.lHook.Add(nHook);

            // Set Thread ACL for hook
            nHook.ThreadACL.SetExclusiveACL(new int[] { 0 }); // Hook all threads except our thread
        }

        // Function Detours
        //-----------
        static private IntPtr CreateFileWDetour(
                IntPtr lpFileName,
                UInt32 dwDesiredAccess,
                UInt32 dwShareMode,
                IntPtr lpSecurityAttributes,
                UInt32 dwCreationDisposition,
                UInt32 dwFlagsAndAttributes,
                IntPtr hTemplateFile)
        {

            // Perform operation in the hooked function
            hDendron.HOOKDAT oHook = new hDendron.HOOKDAT();
            oHook.sHookFunc = "KernelBase!CreateFileW";
            oHook.iType = 0;
            oHook.sHookData = "lpFileName -> " + Marshal.PtrToStringUni(lpFileName);

            // Send data to pipe
            hDendron.passHookDataByPipe(oHook);

            // Return to real function
            return API.CreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
        }

        static void Main(string[] args)
        {
            // Init all hooks
            //-----------
            CreateFileWHook();

            // Start control pipe thread
            //-----------
            Thread ControlThread = new Thread(() => {
                hDendron.listenControlPipe();
            });
            ControlThread.IsBackground = false;
            ControlThread.Start();
        }
    }
}
