namespace RocaTest
{
    using System.Collections.Generic;
    internal class ArgumentParser
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="ArgumentParser"/> class.
        /// </summary>
        /// <param name="args">
        /// The args.
        /// </param>
        internal ArgumentParser(IReadOnlyList<string> args)
        {
            this.DirectoryNames = new List<string>();
            foreach (string arg in args)
            {
                switch (arg.ToLower())
                {
                    case "-my":
                        this.ShouldParseMyStore = true;
                        break;
                    case "-root":
                        this.ShouldParseRootStore = true;
                        break;
                    case "-allstores":
                        this.ShouldParseAllStores = true;
                        break;
                    case "-v":
                        this.Verbose = true;
                        break;
                    default:
                        this.ShouldParseDirectory = true;
                        this.DirectoryNames.Add(arg);
                        break;
                }
            }
        }

        public bool Verbose { get; set; }

        public bool ShouldParseDirectory { get; private set; }
        public bool ShouldParseMyStore { get; private set; }
        public bool ShouldParseRootStore { get; private set; }

        public bool ShouldParseAllStores { get; private set; }

        public List<string> DirectoryNames { get; private set; }

    }
}
