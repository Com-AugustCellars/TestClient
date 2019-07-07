using System;
using System.CodeDom;
using System.Collections.Generic;
using System.Configuration;
using System.IO;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.Threading;
using Com.AugustCellars.CoAP;
using Com.AugustCellars.CoAP.DTLS;
using Com.AugustCellars.CoAP.Log;
using Com.AugustCellars.CoAP.OSCOAP;
using Com.AugustCellars.CoAP.Util;
using Com.AugustCellars.COSE;
using PeterO.Cbor;
using Com.AugustCellars.CoAP.Net;
using Com.AugustCellars.WebToken;
using Org.BouncyCastle.Crypto.Paddings;
#if DEV_VERSION
#if false
using Com.AugustCellars.CoAP.EDHOC;
#endif
using Com.AugustCellars.CoAP.TLS;
#endif

namespace TestClient
{
    class Program
    {
        public static readonly Dictionary<string, OneTlsKey> _TlsKeys = new Dictionary<string, OneTlsKey>();
        // private static CoAPEndPoint _EndPoint = null;
        // private static CoAPEndPoint _DtlsEndpoint = null;
        private static OneKey _TlsKey = null;
        public static readonly Dictionary<string, SecurityContext> _OscopKeys = new Dictionary<string, SecurityContext>();
        private static SecurityContext _CurrentOscoap = null;
        private static readonly Dictionary<string, OneKey> _EdhocValidateKeys = new Dictionary<string, OneKey>();
        private static readonly KeySet _EdhocServerKeys = new KeySet();
        private static readonly List<Option> _Options = new List<Option>();

        private static DispatchTable _dispatchTable = new DispatchTable();
        private static MessageType Con { get; set; } = MessageType.CON;

        private static byte[] Body = null;

#if DO_ACE
        public static AceAuthz AceAuthzHandler = null;
#endif

        public static Uri Host { get; set; }
        public static System.Net.IPEndPoint LocalIp { get; set; }
        public static string Transport { get; set; } = "UDP"; 

        static void Main(string[] args)
        {
            string script = null;

#if false
            {
                //  Generate a pair of CWT messages signed by a third key.

                OneKey clientKey = OneKey.GenerateKey( AlgorithmValues.ECDSA_256, GeneralValues.KeyType_EC);
                OneKey serverKey = OneKey.GenerateKey(AlgorithmValues.ECDSA_256, GeneralValues.KeyType_EC);
                OneKey caKey = OneKey.GenerateKey(AlgorithmValues.ECDSA_256, GeneralValues.KeyType_EC);

                CWT clientCwt = new CWT();
                clientCwt.Cnf = new Confirmation(clientKey.PublicKey());
                clientCwt.SigningKey = caKey;
                CBORObject clientCwtCbor = clientCwt.EncodeToCBOR();
                string clientCwtStr = clientCwtCbor.ToString();
                byte[] clientCwtBytes = clientCwt.EncodeToBytes();

                CWT serverCwt = new CWT() {
                    Cnf = new Confirmation(serverKey),
                    SigningKey = caKey
                };
                CBORObject serverCwtCbor = serverCwt.EncodeToCBOR();
                string serverCwtStr = serverCwtCbor.ToString();
                byte[] serverCwtBytes = serverCwt.EncodeToBytes();

                string caStr = caKey.EncodeToCBORObject().ToString();

            }
#endif

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

            FillDispatchTable(_dispatchTable);
#if DO_ACE
            AceAuthz.AddCommands(_dispatchTable);

            //  Setup plain OAuth
            AceAuthzHandler = new AceAuthz();

#endif
#if DO_RD
            ResourceDirectory.AddCommands(_dispatchTable);
#endif




            if (script != null) {
                TextReader x = new StreamReader(script);
                RunScript(x);
                x.Dispose();
            }


            RunScript(Console.In);

        }

        static void FillDispatchTable(DispatchTable table)
        {
            table.Add("signal", new Dispatch("Send signal message to server",
                                             "Signal <Msg> <Uri>\nMsg is one of 'Ping', 'Pong', 'Release', 'Abort'",
                                             SendSignal));
            table.Add("get",
                      new Dispatch("Send GET method to server", "Get <uri> [<body>]", RunCoapCommand));
            table.Add("put",
                      new Dispatch("Send PUT method to server", "put <uri> [<body>]", RunCoapCommand));
            table.Add("delete",
                      new Dispatch("Send DELTE method to server", "delete <uri> [<body>]", RunCoapCommand));
            table.Add("post",
                      new Dispatch("Send POST method to server", "post <uri> [<body>]", RunCoapCommand));
            table.Add("fetch",
                      new Dispatch("Send FETCH method to server", "fetch <uri> [<body>]", RunCoapCommand));
            table.Add("patch",
                      new Dispatch("Send PATCH method to server", "patch <uri> [<body>]", RunCoapCommand));
            table.Add("ipatch",
                      new Dispatch("Send IPATCH method to server", "ipatch <uri> [<body>]", RunCoapCommand));
            table.Add("observe",
                      new Dispatch("Send OBSERVE method to server", "observe <uri> [<body>]", RunCoapCommand));
            table.Add("unobserve",
                      new Dispatch("Send UNOBSERVE method to server", "unobserve <uri> [<body>]", RunCoapCommand));
            table.Add("discover",
                      new Dispatch("Send DISCOVER method to server", "discover <uri> [<body>]", RunCoapCommand));
            table.Add("con", new Dispatch("Use CON or NON for messages", "con [YES|NO]", SetConState));
            table.Add("sleep", new Dispatch("Sleep for n seconds", "sleep <seconds>", 
                                            m => Thread.Sleep(int.Parse(m[1]) * 1000)));

            table.Add("payload", 
                new Dispatch("Set the payload with CBOR diag value", "payload <cbor diag>", RunSetPayload));

            table.Add("host", new Dispatch("Set a default host to be used", "host [<uri>]", SetHost));
            table.Add("set-transport", new Dispatch("Set the transport to default to if not in the URL", 
                                                    "set-transport UDP|TCP", SetTransport));
            table.Add("local", new Dispatch("Set the local address to send from", "local [<uri>]", SetLocal));

            table.Add("add-tlskey", new Dispatch("Add a named TLS key to the dictionary", "add-tlskey ????", AddTlsKey));
            table.Add("add-tlscwt", new Dispatch("Add a named CWT for TLS to the dictionary", "add-tlscwt name CWT PrivateKey", AddTlsCwt));
            table.Add("set-tlskey", new Dispatch("Set the default TLS key to use", "set-tlskey [key-name]", SetTlsKey));
            table.Add("add-cwtroot", new Dispatch("Add a key to the CWT trust store", "add-cwtroot key", AddCwtRoot));

            table.Add("etag", new Dispatch("Manipulate ETag behavior", "etag [None|clear|last|add|all]", ETagCommands));
            table.Add("if-match", new Dispatch("Set If-Match message options", "if-match [all|none|last]", IfMatchCommands));

#region OSCORE
            //  OSCORE Functions
            table.Add("add-oscore", new Dispatch("Add a OSCORE key to the key set", "add-oscore key-name key-value", AddOscoreKey));
            table.Add("add-group-oscore", new Dispatch("Add a Group OSCORE key to the key set", "add-oscore key-name key-value", AddGroupOscoreKey));
            table.Add("set-oscore", new Dispatch("Select an score key to use", "set-oscore [key-name]", UseOscoreKey));
            table.Add("use-oscore", new Dispatch("Select an score key to use", "use-oscore [key-name]", UseOscoreKey));
            table.Add("run-oscore-test", new Dispatch("Run a specific oscore text", "run-score-test testNumber", RunOscoreText));
            table.Add("set-oscore-piv", new Dispatch("Set the PIV value for the current oscore key", "set-oscore-piv pivNumber", SetOscorePiv));
#endregion

        }

        static void RunSetPayload(string[] cmds)
        {
            if (cmds.Length != 2) {
                Console.WriteLine("Incorrect command");
                return;
            }

            CBORObject cbor = CBORDiagnostics.Parse(cmds[1]);
            Body = cbor.EncodeToBytes();


        }

        static List<byte[]> ETagList = new List<byte[]>();
        private static int ETagOption = 0;

        static void ETagCommands(string[] cmds)
        {
            if (cmds.Length == 1) {
                Console.WriteLine("Incorrect number of arguments");
                return;
            }

            switch (cmds[1].ToLower()) {
                case "add":
                    try {
                        CBORObject o = CBORDiagnostics.Parse(cmds[2]);
                        ETagList.Add(o.GetByteString());
                    }
                    catch {
                        Console.WriteLine("Error in command");                        
                    }
                    break;

                case "all":
                    ETagOption = 2;
                    break;

                case "clear":
                    ETagList.Clear();
                    break;

                case "last":
                    ETagOption = 1;
                    break;

                case "none":
                    ETagOption = 0;
                    break;

                default:
                    Console.WriteLine("Unknown option");
                    break;
            }
        }

        private static int IfMatchOption = 0;
        static void IfMatchCommands(string[] cmds)
        {
            if (cmds.Length == 1) {
                Console.WriteLine("Incorrect number of arguments");
                return;
            }

            switch (cmds[1].ToLower()) {
            case "all":
                IfMatchOption = 2;
                break;

            case "last":
                IfMatchOption = 1;
                break;

            case "none":
                IfMatchOption = 0;
                break;

            default:
                Console.WriteLine("Unknown option");
                break;
            }
        }

        static void SetConState(string[] cmds)
        {
            if (cmds.Length > 2) {
                Console.WriteLine("Incorrect number of arguments");
                return;
            }

            if (cmds.Length == 1) {
                Con = MessageType.CON;
            }
            else {
                switch (cmds[1].ToLower()) {
                    case "yes":
                        Con = MessageType.CON;
                        break;

                    case "no":
                        Con = MessageType.NON;
                        break;

                    case "ack":
                        Con = MessageType.ACK;
                        break;

                    case "rst":
                        Con = MessageType.RST;
                        break;

                    default:
                        Console.WriteLine("Must be 'yes' or 'no'");
                        break;
                }
            }
        }

        static void RunScript(TextReader stream)
        {
            do {
                string command = stream.ReadLine();
                if (command == null) break;
                if (stream != Console.In) {
                    Console.WriteLine(">> " + command);
                }

                string[] cmds = Tokenize(command);

                RunCommand(cmds);


            } while (true);

        }

        static void RunCommand(string[] commands)
        {
            if (commands.Length == 0) return;


            try {

                switch (commands[0].ToUpper()) {
                default:
                    _dispatchTable.Execute(commands);
                    break;


                case "SCRIPT":
                    TextReader x = new StreamReader(commands[1]);
                    RunScript(x);
                    x.Dispose();
                    break;



                case "COMMENT":
                    break;

                case "EXIT":
                    Environment.Exit(0);
                    break;

                case "PAUSE":
                    Console.ReadLine();
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
                    switch (typ) {
                    case OptionType.ContentFormat:
                    case OptionType.Accept:
                        if (commands.Length == 2) {
                            _Options.Add(Option.Create(typ));
                        }
                        else {
                            for (int i = 2; i < commands.Length; i++) {
                                int val = MediaType.ApplicationLinkFormat;
                                if (int.TryParse(commands[i], out val)) {
                                    _Options.Add(Option.Create(typ, val));
                                }
                                else {
                                    Console.WriteLine($"Bad option value '{commands[i]}'");
                                }
                            }
                        }

                        break;

                    case OptionType.Unknown:
                        Console.WriteLine("Unrecognized type string");
                        return;

                    default:
                        if (commands.Length == 2) {
                            _Options.Add(Option.Create(typ));
                        }
                        else {
                            for (int i = 2; i < commands.Length; i++) {
                                _Options.Add(Option.Create(typ, commands[i]));
                            }
                        }

                        break;
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

                case "BODY":
                    if (commands.Length == 1) break;
                    byte[] b = File.ReadAllBytes(commands[1]);
                    Body = b;
                    break;



#if false
                case "EDHOC":
                    RunEdhoc(commands);
                    break;
#endif


#if DEV_VERSION
#endif


                case "EDHOC-ADD-SERVER-KEY":
                    if (commands.Length != 2) {
                        Console.WriteLine("Incorrect number of arguments: " + commands.Length);
                        return;
                    }

                    CBORObject cbor = CBORDiagnostics.Parse(commands[2]);
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
                }
            }
            catch (Exception e) {
                Console.WriteLine("Exception processing command");
                Console.WriteLine(e);
            }
        }

        public static void SetHost(string[] commands)
        {
            if (commands.Length == 1) Host = null;
            else if (commands.Length == 2) {
                Host = new Uri(commands[1]);
            }
            else {
                Console.WriteLine("Wrong number of arguments");
            }
        }

        public static void SetLocal(string[] commands)
        {
            if (commands.Length == 1) LocalIp = null;
            else if (commands.Length == 2) {
                try {
                    LocalIp = new IPEndPoint( IPAddress.Parse(commands[1]), 0);
                }
                catch {
                    Console.WriteLine("Invalid format");
                }
            }
            else {
                Console.WriteLine("Wrong number of arguments");
                return;
            }

            endpoints.Clear();
        }

        public static void SetTransport(string[] commands)
        {
            if (commands.Length == 1) Transport = "UDP";
            else if (commands.Length == 2) {
                switch (commands[1]) {
                    case "UDP":
                    case "TCP":
                        Transport = commands[1];
                        break;

                    default:
                        Console.WriteLine("Unrecognized transport");
                        break;
                }
            }
            else {
                Console.WriteLine("Wrong number of arguments");
            }
        }

        private static void AddTlsCwt(string[] commands)
        {
            if (commands.Length != 4) {
                Console.Write($"Incorrect number of arguments: {commands.Length}");
                return;
            }

            CBORObject cbor = CBORDiagnostics.Parse(commands[2]);
            CWT cwt = CWT.Decode(cbor.EncodeToBytes(), CwtRootKeys, CwtRootKeys);

            cbor = CBORDiagnostics.Parse(commands[3]);
            _TlsKeys.Add(commands[1], new OneTlsKey(cwt, new OneKey(cbor)));
        }

        private static void AddTlsKey(string[] commands)
        {
            if (commands.Length != 3) {
                Console.WriteLine("Incorrect number of arguments: " + commands.Length);
                return;
            }

            CBORObject cbor = CBORDiagnostics.Parse(commands[2]);
            OneKey key = new OneKey(cbor);
            _TlsKeys.Add(commands[1], new OneTlsKey(key));
        }

        private static void SetTlsKey(string[] commands)
        {
            if (commands.Length != 2) {
                currentTlsKey = null;
                return;
            }

            if (!_TlsKeys.ContainsKey(commands[1])) {
                Console.WriteLine($"TLS Key {commands[1]} is not defined");
                return;
            }

            currentTlsKey = commands[1];
        }

        #region OSCORE functions

        private static void AddOscoreKey(string[] cmds)
        {
            if (cmds.Length != 3) {
                Console.WriteLine("Incorrect number of arguments: " + cmds.Length);
                return;
            }

            CBORObject cbor = CBORDiagnostics.Parse(cmds[2]);
            byte[] salt = null;
            if (cbor.ContainsKey(CBORObject.FromObject(6))) {
                salt = cbor[CBORObject.FromObject(6)].GetByteString();
            }

            byte[] contextId = null;
            if (cbor.ContainsKey(CBORObject.FromObject(7))) {
                contextId = cbor[CBORObject.FromObject(7)].GetByteString();
            }

            SecurityContext ctx = SecurityContext.DeriveContext(
                cbor[CBORObject.FromObject(1)].GetByteString(),
                contextId,
                cbor[CBORObject.FromObject(2)].GetByteString(),
                cbor[CBORObject.FromObject(3)].GetByteString(), salt,
                null /*cbor[CoseKeyKeys.Algorithm]*/);

            _OscopKeys.Add(cmds[1], ctx);
        }

        /// <summary>
        /// What the CBOR structure needs to look like:
        /// 
        /// </summary>
        /// <param name="cmds"></param>
        private static void AddGroupOscoreKey(string[] cmds)
        {
            if (cmds.Length != 3) {
                Console.WriteLine("Incorrect number of arguments: " + cmds.Length);
                return;
            }

            CBORObject cbor = CBORDiagnostics.Parse(cmds[2]);
            byte[] salt = null;
            if (cbor.ContainsKey(CoseKeyKeys.slt)) {
                salt = cbor[CoseKeyKeys.slt].GetByteString();
            }

            SecurityContext ctx = SecurityContext.DeriveGroupContext(cbor[CoseKeyParameterKeys.Octet_k].GetByteString(),
                                                                     cbor[CBORObject.FromObject("GroupID")].GetByteString(),
                                                                     cbor[CBORObject.FromObject("sender")][
                                                                         CBORObject.FromObject("ID")].GetByteString(),
                                                                     cbor["sender"]["sign"][CoseKeyKeys.Algorithm],
                                                                     new OneKey(cbor["sender"]["sign"]),
                                                                     null, null, salt, cbor[CoseKeyKeys.Algorithm]);
            foreach (CBORObject recipient in cbor[CBORObject.FromObject("recipients")].Values) {
                OneKey signKey = null;
                if (recipient.ContainsKey("sign")) {
                    signKey = new OneKey(recipient["sign"]);
                }
                ctx.AddRecipient(recipient[CBORObject.FromObject("ID")].GetByteString(), signKey);
            }

            _OscopKeys.Add(cmds[1], ctx);
        }

        private static void UseOscoreKey(string[] cmds)
        {
            if (cmds.Length != 2) {
                Console.WriteLine("Incorrect number of arguments: " + cmds.Length);
                return;
            }

            if (cmds[1] == "NONE") {
                _CurrentOscoap = null;
                return;
            }

            if (!_OscopKeys.ContainsKey(cmds[1])) {
                Console.WriteLine($"OSCOAP Key {cmds[1]} is not defined");
                return;
            }

            _CurrentOscoap = _OscopKeys[cmds[1]];
        }

        private static void RunOscoreText(string[] cmds)
        {

            OscoapTests.RunTest(Int32.Parse(cmds[1]));
        }

        private static void SetOscorePiv(string[] cmds)
        {
            _CurrentOscoap.Sender.SequenceNumber = Int32.Parse(cmds[1]);
        }

        #endregion

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
                            if (Host != null) {
                                uri = new Uri(Host, arg);
                            }
                            else {
                                uri = new Uri(arg);
                            }

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

            request.Type = Con;
            uri = request.URI;

            if (!AddEndPoint(request)) {
                return;
            }

            if (payload != null) {
                int mt = MediaType.TextPlain;
                if (request.HasOption(OptionType.ContentFormat)) {
                    mt = request.ContentFormat;
                }
                request.SetPayload(payload, mt);
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
                        if (response.ContentFormat == MediaType.ApplicationCbor) {
                            CBORObject o = CBORObject.DecodeFromBytes(response.Payload);
                            Console.WriteLine(o.ToString());
                        }
                        Console.WriteLine("Time (ms): " + response.RTT);

                        if (response.HasOption(OptionType.ETag)) {
                            ETagList.AddRange(response.ETags);
                        }

#if DO_ACE
                        if (response.StatusCode == StatusCode.Unauthorized && AceAuthzHandler != null) {
                            AceAuthzHandler.Process(request, response);

                        }
#endif
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

        private static Dictionary<string, int> defaultPort = new Dictionary<string, int>() {
            {"coap+tcp", 5683}, {"coaps+tcp", 5684},
            {"coap+udp", 5683 }, {"coaps+udp", 5684} 
        };
        private static Dictionary<string, CoAPEndPoint> endpoints = new Dictionary<string, CoAPEndPoint>();
        private static string currentTlsKey = null;

        public static bool AddEndPoint(Request request)
        {
            Uri url = request.URI;
            string scheme = url.Scheme;
            string server;

            if (scheme == "coap" || scheme == "coaps") {
                scheme = scheme + "+" + Transport.ToLower();
            }

            int port = url.Port;
            
            if (port == 0) {
                port = defaultPort[scheme];
            }

            server = $"{scheme}://{url.Host}:{port}";

            if (!endpoints.ContainsKey(scheme)) {
                CoAPEndPoint ep;
                

                switch (scheme) {
#if DO_TCP
                    case "coap+tcp":
                        ep = new TCPClientEndPoint();
                        break;

                    case "coaps+tcp":
                        if (currentTlsKey == null) {
                            Console.WriteLine("No current TLS key specified");
                            return false;
                        }
                        TLSClientEndPoint tep = new TLSClientEndPoint(_TlsKeys[currentTlsKey]);
                        // tep.TlsEventHandler += OnTlsEvent;
                        ep = tep;
                        break;
#endif

                    case "coap+udp":
                        if (LocalIp != null) {
                            ep = new CoAPEndPoint(LocalIp);
                        }
                        else {
                            ep = new CoAPEndPoint();
                        }
                        break;

                    case "coaps+udp":
                        if (currentTlsKey == null) {
                            Console.WriteLine("No current TLS key specified");
                            return false;
                        }

                        DTLSClientEndPoint dep;
                        if (LocalIp != null) {
                            dep = new DTLSClientEndPoint(_TlsKeys[currentTlsKey].RawPublicKey, LocalIp);
                        }
                        else {
                            dep = _TlsKeys[currentTlsKey].GetClientEndPoint();
                        }

                        dep.TlsEventHandler += OnTlsEvent;
                        ep = dep;
                        break;

                    default:
                        Console.WriteLine("Unknown schema");
                        return false;
                }

                endpoints[server] = ep;
                ep.Start();

                ep.ReceivingSignalMessage += (sender, args) =>
                {
                    Console.WriteLine("Signal message from {0}", "???");
                    Console.WriteLine(args.Message.ToString());
                };
            }

            request.EndPoint = endpoints[server];


            return true;
        }

        public static Request NewRequest(string method, Uri uriIn)
        {
            Request request;
            switch (method) {
                case "POST":
                    request = Request.NewPost();
                    if (Body != null) {
                        request.Payload = Body;
                    }
                    break;

                case "PUT":
                    request = Request.NewPut();
                    if (Body != null) {
                        request.Payload = Body;
                    }
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
                    if (Body != null) {
                        request.Payload = Body;
                    }
                    break;

                case "IPATCH":
                    request = new Request(Method.iPATCH);
                    if (Body != null) {
                        request.Payload = Body;
                    }
                    break;

                default:
                    return null;
            }

            if (!uriIn.IsAbsoluteUri) {
                uriIn = new Uri(Host + uriIn.ToString());
            }
            request.URI = uriIn;

            SetTagOptions(request, OptionType.ETag, ETagOption);
            SetTagOptions(request, OptionType.IfMatch, IfMatchOption);

            request.AddOptions(_Options);
            if (_CurrentOscoap != null) {
                request.OscoapContext = _CurrentOscoap;
            }


            return request;
        }

        private static void SetTagOptions(Request request, OptionType optionId, int choice)
        {
            switch (choice) {
                case 0: // nothing
                    break;

                case 1: // last
                    if (ETagList.Count > 0) {
                        request.AddOption(Option.Create(optionId, ETagList.Last()));
                    }
                    break;

                case 2: // All
                    foreach (byte[] tag in ETagList) {
                        request.AddOption(Option.Create(optionId, tag));
                    }
                    break;
            }
        }


        public static void SendSignal(string[] args)
        {
            int index = 0;
            Method method = 0;
            Uri uri = null;
            string payload = null;

            foreach (string arg in args) {
                switch (index) {
                    case 0:
                        break;

                    case 1:
                        switch (arg.ToUpper()) {
                            case "PING":
                                method = (Method) SignalCode.Ping;
                                break;

                            case "PONG":
                                method = (Method) SignalCode.Pong;
                                break;

                            case "RELEASE":
                                method = (Method) SignalCode.Release;
                                break;

                            case "ABORT":
                                method = (Method) SignalCode.Abort;
                                break;

                            default:
                                Console.WriteLine("Unknown signal");
                                return;
                        }
                        break;

                    case 2:
                        try {
                            uri = new Uri(Host, arg);

                        }
                        catch (Exception ex) {
                            Console.WriteLine("failed parsing URI: " + ex.Message);
                            return;
                        }
                        break;

                    case 3:
                        payload = arg;
                        break;

                    default:
                        Console.WriteLine("Unexpected argument: " + arg);
                        break;

                }
                index++;
            }

            if (method == 0) {
                Console.WriteLine("Requires method and uri");
                return;
            }

            if (uri == null) {
                uri = new Uri(Host, "/");
            }

            if (!uri.IsAbsoluteUri) {
                uri = new Uri(Host + uri.ToString());
            }


            Request request = new Request(method) {
                URI = uri
            };

            if (!AddEndPoint(request)) {
                return;
            }
            

            if (payload != null) {
                if (payload.ToUpper() == "CUSTODY") {
                    request.SetOption(Option.Create(OptionType.Signal_Custody));
                }
                else {
                    request.SetPayload(payload, MediaType.TextPlain);
                }
            }


            try {
                request.Respond += delegate (Object sender, ResponseEventArgs e)
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

        private static string[] Tokenize(string input)
        {
            int start = 0;
            bool fInQuote = false;
            List<string> tokens = new List<string>();

            for (int i = 0; i < input.Length; i++) {
                switch (input[i]) {
                    case ' ':
                        if (!fInQuote) {
                            if (i  > start) {
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

#if false
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
                case "CONTENT-TYPE": return OptionType.ContentType;
                case "ACCEPT": return OptionType.Accept;
                case "IF-NONE": return OptionType.IfNoneMatch;
                default: return OptionType.Unknown;
            }
        }

        static void OnTlsEvent(Object o, TlsEvent e)
        {

        }


        static readonly KeySet CwtRootKeys = new KeySet();

        static void AddCwtRoot(string[] cmds)
        {
            if (cmds.Length != 2) {
                Console.WriteLine("wrong number of parameters");
                return;
            }
            CBORObject cbor = CBORDiagnostics.Parse(cmds[1]);
            CwtRootKeys.AddKey(new OneKey(cbor));
        }

        public class OneTlsKey
        {
            public readonly OneKey RawPublicKey;
            public readonly CWT Cwt;
            public readonly byte[] ClientCertificate;

            public OneTlsKey(OneKey key)
            {
                RawPublicKey = key;
            }

            public OneTlsKey(CWT cwt, OneKey privKey)
            {
                Cwt = cwt;
                RawPublicKey = privKey;
            }

            public DTLSClientEndPoint GetClientEndPoint()
            {               
                if (Cwt != null) { 
                    return new DTLSClientEndPoint(Cwt, RawPublicKey, CwtRootKeys); // , CwtRootKeys);
                }

                if (RawPublicKey != null)
                {
                    return new DTLSClientEndPoint(RawPublicKey);
                }

                throw new Exception("No");
            }
        }
    }
}
