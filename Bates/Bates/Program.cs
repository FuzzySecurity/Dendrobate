using System;
using CommandLine;

namespace Bates
{
    class Program
    {
        class ArgOptions
        {
            [Option(null, "listen")]
            public Int32 iListen { get; set; }

            [Option(null, "kill")]
            public Boolean bKill { get; set; }

            [Option(null, "help")]
            public Boolean bHelp { get; set; }
        }

        static void Main(string[] args)
        {
            // Because ASCII
            hBates.getASCII();

            // Parse args
            var ArgOptions = new ArgOptions();
            if (CommandLineParser.Default.ParseArguments(args, ArgOptions))
            {
                if (ArgOptions.bHelp || args.Length == 0)
                {
                    hBates.getHelp();
                } else
                {
                    if (ArgOptions.bKill)
                    {
                        Boolean bSent = hBates.passControlCodeByPipe();
                        if (bSent)
                        {
                            Console.WriteLine("\n[+] Dendron client un-hooking..");
                        } else
                        {
                            Console.WriteLine("\n[!] Failed to talk to Dendron client..");
                        }
                        return;
                    } else if (ArgOptions.iListen != 0)
                    {
                        hBates.ListenNamedPipe(ArgOptions.iListen);
                        return;
                    } else
                    {
                        hBates.getHelp();
                    }
                }
            } else
            {
                hBates.getHelp();
            }
        }
    }
}
