using System;
using System.Collections.Generic;
using System.ComponentModel.Design;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Com.AugustCellars.CoAP;
using Com.AugustCellars.CoAP.DTLS;
using Com.AugustCellars.CoAP.Log;
using Com.AugustCellars.CoAP.OSCOAP;
using Com.AugustCellars.CoAP.Util;
using Com.AugustCellars.COSE;
using PeterO.Cbor;
using Com.AugustCellars.CoAP.Net;
#if DEV_VERSION
using Com.AugustCellars.CoAP.EDHOC;
using Com.AugustCellars.CoAP.TLS;
#endif

namespace TestClient
{
    class Program
    {
        private static readonly Dictionary<string, OneKey> _TlsKeys = new Dictionary<string, OneKey>();
        private static CoAPEndPoint _EndPoint = null;
        private static DTLSClientEndPoint _DtlsEndpoint = null;
        private static readonly Dictionary<string, SecurityContext> _OscopKeys = new Dictionary<string, SecurityContext>();
        private static SecurityContext _CurrentOscoap = null;
        private static readonly Dictionary<string, OneKey> _EdhocValidateKeys = new Dictionary<string, OneKey>();
        private static readonly KeySet _EdhocServerKeys = new KeySet();
        private static readonly List<Option> _Options = new List<Option>();

        public static Uri Host { get; set; }


        static void Main(string[] args)
        {
            string script = null;

            LogManager.Instance = new FileLogManager(Console.Out);

            foreach (string arg in args) {
                if (arg[0] == '-') {
                    if (arg.StartsWith("--script=")) {
                        script = arg.Substring(9);
                    }

                }
                else {
                    
                }
            }

            if (script != null) {
                TextReader x = new StreamReader(script);
                RunScript(x);
                x.Dispose();
            }

            RunScript(Console.In);

        }

        static void RunScript(TextReader stream)
        {
            do {
                string command = stream.ReadLine();
                if (command == null) break;
                if (stream != Console.In) {
                    Console.WriteLine(">> " + command);
                }

#if true
                string[] cmds = Tokenize(command);
#else
                string[] cmds = Regex.Matches(command, @"[\""].+?[\""]|[^ ]+")
                    .Cast<Match>()
                    .Select(m => m.Value)
                    .ToArray();
                for (int i=0; i< cmds.Length; i++) if (cmds[i][0] == '"') cmds[i] = cmds[i].Substring(1, cmds[i].Length - 2); 
#endif

                RunCommand(cmds);


            } while (true);

        }

        static void RunCommand(string[] commands)
        {
            if (commands.Length == 0) return;

            switch (commands[0].ToUpper()) {
                case "GET":
                case "PUT":
                case "DELETE":
                case "POST":
                case "FETCH":
                case "PATCH":
                case "IPATCH":
                case "OBSERVE":
                case "UNOBSERVE":
                case "DISCOVER":
                    RunCoapCommand(commands);
                    break;

                case "SLEEP":
                    Thread.Sleep(int.Parse(commands[1]) * 1000);
                    break;

                case "SCRIPT":
                    TextReader x = new StreamReader(commands[1]);
                    RunScript(x);
                    x.Dispose();
                    break;

                case "SET-ENDPOINT":
		    if (_EndPoint == null) {
                        _EndPoint.Stop();
			 _EndPoint.Dispose();
		       _EndPoint = null;
		    }
		    
                    switch (commands[1]) {
                        case "UDP":
                            _EndPoint = null;
                            break;

#if DEV_VERSION
                        case "TCP":
                            if (commands.Length == 3) {
                                _EndPoint = new TCPClientEndPoint(Int32.Parse(commands[2]));
                            }
                            else {
                                _EndPoint = new TCPClientEndPoint();
                            }
                            _EndPoint.Start();
                            break;
#endif // DEV_VERSION

                        default:
                            Console.WriteLine("Unknown endpoint type");
                            break;
                    }
                    break;

                case "ADD-TLSKEY":
                    if (commands.Length != 3) {
                        Console.WriteLine("Incorrect number of arguments: " + commands.Length);
                        return;
                    }

                    CBORObject cbor = CBORDiagnostics.Parse(commands[2]);
                    OneKey key = new OneKey(cbor);
                    _TlsKeys.Add(commands[1], key);
                    break;

                case "USE-TLSKEY":
                    if (commands.Length != 2) {
                        Console.WriteLine("Incorrect number of arguments: " + commands.Length);
                        return;
                    }
                    if (!_TlsKeys.ContainsKey(commands[1])) {
                        Console.WriteLine($"TLS Key {commands[1]} is not defined");
                        return;
                    }

                    if (_DtlsEndpoint != null) {
                        _DtlsEndpoint.Stop();
                        _DtlsEndpoint.Dispose();
                        _DtlsEndpoint = null;
                    }

                    _DtlsEndpoint = new DTLSClientEndPoint(_TlsKeys[commands[1]]);
                    _DtlsEndpoint.Start();
                    break;

                case "COMMENT":
                    break;

                case "EXIT":
                    Environment.Exit(0);
                    break;

                case "PAUSE":
                    Console.ReadLine();
                    break;

                case "PAYLOAD":

                    break;

                case "TIMEOUT":
                    break;

                case "LOG-LEVEL":
                    if (commands.Length != 2) {
                        Console.WriteLine("Incorrect number of args");
                        return;
                    }
                    switch (commands[1].ToUpper()) {
                        case "INFO":
                            LogManager.Level = LogLevel.Info;
                            break;

                        case "NONE":
                            LogManager.Level = LogLevel.None;
                            break;

                        case "FATAL":
                            LogManager.Level = LogLevel.Fatal;
                            break;

                        default:
                            Console.WriteLine("Unknown level");
                            break;
                    }
                    break;

                case "LOG-TO":
                    break;

                case "OPTION":
                    OptionType typ = GetOptionType(commands[1]);
                    if (commands.Length == 2) {
                        _Options.Add(Option.Create(typ));
                    }
                    else {
                        for (int i = 2; i < commands.Length; i++) {
                            _Options.Add(Option.Create(typ, commands[i]));
                        }
                    }
                    break;

                case "CLEAR-OPTION":
                    if (commands.Length == 1) {
                        _Options.Clear();
                        return;

                    }
                    typ = GetOptionType(commands[1]);
                    List<Option> del = new List<Option>();
                    foreach (Option op in _Options) {
                        if (op.Type == typ) del.Add(op);
                    }
                    foreach (Option op in del) _Options.Remove(op);
                    break;

                case "HOST":
                    if (commands.Length == 1) Host = null;
                    else if (commands.Length == 2) Host = new Uri(commands[1]);
                    else Console.WriteLine("Wrong number of arguments");
                    break;

#if DEV_VERSION
                case "EDHOC":
                    RunEdhoc(commands);
                    break;
#endif

                case "ADD-OSCOAP":
                    if (commands.Length != 3) {
                        Console.WriteLine("Incorrect number of arguments: " + commands.Length);
                        return;
                    }

                    cbor = CBORDiagnostics.Parse(commands[2]);
                    SecurityContext ctx = SecurityContext.DeriveContext(
                        cbor[CoseKeyParameterKeys.Octet_k].GetByteString(),
                        cbor[CBORObject.FromObject("RecipID")].GetByteString(),
                        cbor[CBORObject.FromObject("SenderID")].GetByteString(), null,
                        cbor[CoseKeyKeys.Algorithm]);

                    _OscopKeys.Add(commands[1], ctx);

                    break;

#if DEV_VERSION
                case "ADD-OSCOAP-GROUP":
                    if (commands.Length != 3) {
                        Console.WriteLine("Incorrect number of arguments: " + commands.Length);
                        return;
                    }
                    cbor = CBORDiagnostics.Parse(commands[2]);
                    ctx = SecurityContext.DeriveGroupContext(cbor[CoseKeyParameterKeys.Octet_k].GetByteString(), cbor[CoseKeyKeys.KeyIdentifier].GetByteString(),
                        cbor[CBORObject.FromObject("sender")][CBORObject.FromObject("ID")].GetByteString(), null, null, cbor[CoseKeyKeys.Algorithm]);
                    ctx.Sender.SigningKey = new OneKey(cbor["sender"]["sign"]);
                    foreach (CBORObject recipient in cbor[CBORObject.FromObject("recipients")].Values) {
                        ctx.AddRecipient(recipient[CBORObject.FromObject("ID")].GetByteString(), new OneKey(recipient["sign"]));
                    }

                    _OscopKeys.Add(commands[1], ctx);
                    break;
#endif

                case "USE-OSCOAP":
                    if (commands.Length != 2) {
                        Console.WriteLine("Incorrect number of arguments: " + commands.Length);
                        return;
                    }

                    if (commands[1] == "NONE") {
                        _CurrentOscoap = null;
                        return;
                    }

                    if (!_OscopKeys.ContainsKey(commands[1])) {
                        Console.WriteLine($"OSCOAP Key {commands[1]} is not defined");
                        return;
                    }

                    _CurrentOscoap = _OscopKeys[commands[1]];
                    break;

                case "OSCOAP-TEST":
                    OscoapTests.RunTest(Int32.Parse(commands[1]) );
                    break;

                case "OSCOAP-PIV":
                    _CurrentOscoap.Sender.SequenceNumber = Int32.Parse(commands[1]);
                    break;

                case "EDHOC-ADD-SERVER-KEY":
                    if (commands.Length != 2) {
                        Console.WriteLine("Incorrect number of arguments: " + commands.Length);
                        return;
                    }

                    cbor = CBORDiagnostics.Parse(commands[2]);
                    _EdhocServerKeys.AddKey(new OneKey(cbor));
                    break;

                case "EDHOC-ADD-USER-KEY":
                    if (commands.Length != 3) {
                        Console.WriteLine("Incorrect number of arguments: " + commands.Length);
                        return;
                    }

                    cbor = CBORDiagnostics.Parse(commands[2]);
                    _EdhocValidateKeys.Add(commands[1], new OneKey(cbor));
                    break;


                case "HELP":
                    PrintHelp();
                    break;

                default:
                    Console.WriteLine("Unknown command: " + commands[0]);
                    break;
            }
        }


        public static void RunCoapCommand(string[] args)
        {
            int index = 0;
            string method = null;
            Uri uri = null;
            string payload = null;

            foreach (string arg in args) {
                switch (index) {
                    case 0:
                        method = arg.ToUpper();
                        break;

                    case 1:
                        try {
                            uri = new Uri(Host, arg);

                        }
                        catch (Exception ex) {
                            Console.WriteLine("failed parsing URI: " + ex.Message);
                            return;
                        }
                        break;

                    case 2:
                        payload = arg;
                        break;

                    default:
                        Console.WriteLine("Unexpected argument: " + arg);
                        break;
                
                }
                index++;
            }

            if (method == null || uri == null) {
                Console.WriteLine("Requires method and uri");
                return;
            }

            Request request = NewRequest(method, uri);
            if (request == null) {
                Console.WriteLine("Unknown method: " + method);
                return;
            }

            uri = request.URI;
            request.EndPoint = _EndPoint;


            if (uri.Scheme == "coaps") {
                if (_DtlsEndpoint == null) {
                    Console.WriteLine("Need to defined the TLS key before using this command");
                    return;
                }
                request.EndPoint = _DtlsEndpoint;
            }

            if (payload != null) {
                request.SetPayload(payload, MediaType.TextPlain);
            }


            try {
                request.Respond += delegate(Object sender, ResponseEventArgs e)
                {
                    Response response = e.Response;
                    if (response == null) {
                        Console.WriteLine("Request timeout");
                    }
                    else {
                        Console.WriteLine(Utils.ToString(response));
                        Console.WriteLine("Time (ms): " + response.RTT);
                    }
                };
                request.Send();
                Thread.Sleep(1000);

            }
            catch (Exception ex) {
                Console.WriteLine("Failed executing request: " + ex.Message);
                Console.WriteLine(ex);
            }
        }

        private static Request NewRequest(string method, Uri uriIn)
        {
            Request request;
            switch (method) {
                case "POST":
                    request = Request.NewPost();
                    break;

                case "PUT":
                    request = Request.NewPut();
                    break;

                case "DELETE":
                    request = Request.NewDelete();
                    if ((string.IsNullOrEmpty(uriIn.AbsolutePath) || uriIn.AbsolutePath.Equals("/"))) {
                        uriIn = new Uri(uriIn + "/.well-known/core" + uriIn.Query);
                    }


                    break;

                case "GET":
                    request = Request.NewGet();
                    break;

                case "DISCOVER":
                    request = Request.NewGet();
                    break;

                case "OBSERVE":
                    request = Request.NewGet();
                    request.MarkObserve();
                    break;

                case "UNOBSERVE":
                    request = Request.NewGet();
                    request.Observe = 0;
                    break;

                case "FETCH":
                    request = new Request(Method.FETCH);
                    break;

                case "PATCH":
                    request = new Request(Method.PATCH);
                    break;

                case "IPATCH":
                    request = new Request(Method.iPATCH);
                    break;

                default:
                    return null;
            }

            if (!uriIn.IsAbsoluteUri) {
                uriIn = new Uri(Host + uriIn.ToString());
            }
            request.URI = uriIn;

            request.AddOptions(_Options);
            if (_CurrentOscoap != null) {
                request.OscoapContext = _CurrentOscoap;
            }


            return request;
        }


        private static string[] Tokenize(string input)
        {
            int start = 0;
            bool fInQuote = false;
            List<string> tokens = new List<string>();

            for (int i = 0; i < input.Length; i++) {
                switch (input[i]) {
                    case ' ':
                        if (!fInQuote) {
                            if (i - 1 != start) {
                                tokens.Add(input.Substring(start, i - start));
                            }
                            start = i + 1;
                        }
                        break;

                    case '"':
                        fInQuote = !fInQuote;
                        break;

                    case '\\':
                        i += 1;
                        break;

                    default:
                        break;
                }
            }

            if (start != input.Length) {
                tokens.Add(input.Substring(start, input.Length - start));
            }

            for (int i = 0; i < tokens.Count; i++) {
                if (tokens[i][0] == '"') {
                    tokens[i] = tokens[i].Substring(1, tokens[i].Length - 2);
                }

                tokens[i] = tokens[i].Replace("\\\"", "\"");

            }

            return tokens.ToArray();
        }

#if DEV_VERSION
        /// <summary>
        /// Run the EDHOC protocol
        /// Command line:  EDHOC <New key name> <validate key> URL
        /// </summary>
        /// <param name="cmds"></param>
        static void RunEdhoc(string[] cmds)
        {
            if (cmds.Length != 4) {
                Console.WriteLine("wrong number of arguments");
                return;
            }

            EdhocInitiator send = new EdhocInitiator(_EdhocValidateKeys[cmds[2]]);
            

            byte[] data = send.CreateMessage1();

            Request req = NewRequest("POST", new Uri(cmds[3]));
            req.Payload = data;

            req.Send();
            Response response = req.WaitForResponse();

            send.ParseMessage2(response.Payload, _EdhocServerKeys);

            data = send.CreateMessage3();

            req = NewRequest("POST", new Uri(cmds[3]));
            req.Payload = data;

            req.Send();
            response = req.WaitForResponse();

            _OscopKeys[cmds[1]] = send.CreateSecurityContext();
        }
#endif // DEV_VERSION

        static OptionType GetOptionType(string name)
        {
            switch (name.ToUpper()) {
                case "MAX-AGE": return OptionType.MaxAge;
                default: return OptionType.Unknown;
            }
        }


        static void PrintHelp()
        {
            Console.WriteLine("Command syntax:");
            Console.WriteLine();
            Console.WriteLine("VERB <uri> <payload> - Execute a CoAP operation - VERB = GET, PUT, DELETE, POST, FETCH, PATHC, IPATCH, OBSERVE, UNOBSERVE, DISCOVER");
            Console.WriteLine("COMMENT <text> - comment out the line");
            Console.WriteLine("EXIT - exit the program");
            Console.WriteLine("LOG-LEVEL <level> - what level of logging to use - NONE, INFO, FATAL");
            Console.WriteLine("PAUSE - wait until a new line is entered");
            Console.WriteLine("SLEEP n - sleep for n seconds");
            Console.WriteLine("SCRIPT <filename> - run the commands in the script file");

            Console.WriteLine();
            Console.WriteLine("ADD-TLSKEY <name> <key> - Add key to the TLS key set");
            Console.WriteLine("USE-TLSKEY <name> - use the key associated with the name for all coaps messages");
            Console.WriteLine();
            Console.WriteLine("ADD-OSCOAP <name> <key> - Add key to the OSCOAP key set");
            Console.WriteLine("ADD-OSCOAP-GROUP <name> <key> - Add the key as a group descriptor for OSCOAP");
            Console.WriteLine("USE-OSCOAP <name> - Use the named value for all coap messages, a name of 'NONE' clears this field");
            Console.WriteLine("OSCOAP-PIV <number> - Set the PIV for the sender");
            Console.WriteLine("OSCOAP-TEST <number> - execute oscoap test n - value of 0 to ?");

            Console.WriteLine();
            Console.WriteLine("EDHOC <name> <initiator key> <url> - Create an oscoap key of <name> using <initiator> for validation");
            Console.WriteLine("EDHOC-ADD-SERVER-KEY <key> - Add key to the set of server validation keys - only required for asymmetric keys");
            Console.WriteLine("EDHOC-ADD-USER-KEY <name> <key> - Add key to the edhoc key set");

        }
    }
}
