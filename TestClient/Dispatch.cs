using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;

namespace TestClient
{
    class Dispatch
    {
        public Action<string[]>  Action { get; }
        public string HelpLine { get; }
        public string Description { get;  }

        public Dispatch(string help, string description, Action<string[]> action)
        {
            Action = action;
            HelpLine = help;
            Description = description;
        }

    }

    class DispatchTable
    {
        readonly Dictionary<string, Dispatch> _table = new Dictionary<string, Dispatch>();

        public DispatchTable()
        {
            Add("help", new Dispatch("print help", "", PrintHelp));
        }

        public void Add(string cmd, Dispatch action)
        {
            cmd = cmd.ToLower();
            if (_table.ContainsKey(cmd)) {
                Console.WriteLine("DUPLICATE command {0}", cmd);
                Debug.Assert(true);
                return;
            }

            _table[cmd] = action;
        }

        public void Execute(string[] cmds)
        {
            string cmd = cmds[0].ToLower();

            if (!_table.ContainsKey(cmd)) {
                Console.WriteLine("Unknown command {0}", cmd);
                return;
            }

            _table[cmd].Action(cmds);
        }

        public void PrintHelp(string[] cmds)
        {
            if (cmds.Length == 1) {
                List<string> keys = _table.Keys.ToList();
                keys.Sort();

                foreach (string key in keys) {
                    Console.WriteLine("{0}\t{1}", key, _table[key].HelpLine);
                }
            }
            else {
                string cmd = cmds[1].ToLower();
                if (_table.ContainsKey(cmd)) {
                    Console.WriteLine(_table[cmd].Description);
                }
                else {
                    Console.WriteLine("No such command");
                }
            }
        }
    }
}
